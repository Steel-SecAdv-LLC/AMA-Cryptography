/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ctoperand -- a Valgrind tool that reports every guest instruction which
 * consumes a secret-derived operand.
 *
 * Why this exists
 * ---------------
 * The Memcheck taint lane (tools/check_ghash_constant_time.py --taint) marks
 * a secret undefined and reports every conditional jump, conditional move and
 * memory address that depends on it.  Memcheck propagates definedness through
 * arithmetic and does NOT report an arithmetic instruction whose operand is
 * undefined: `div`, `mulsd`, `sqrtsd` on a secret all pass it silently.  That
 * is the variable-latency-operand class (KyberSlash is its best-known
 * member), and no gate in this repository could see it except for the
 * divide-instruction inventory in tools/check_secret_division.py, which reads
 * the object statically and cannot tell a secret operand from a public one.
 *
 * This tool answers the missing question dynamically.  It keeps its own
 * byte-granular taint shadow for memory and for the guest register file, and
 * a one-bit taint shadow for every IR temporary, propagated pessimistically
 * (the result of an operation is tainted when any operand is).  At the end of
 * every guest instruction it asks "did any IR expression evaluated for this
 * instruction read a tainted value?" and, when the answer is yes, records the
 * instruction's address.  The Python gate (tools/check_ct_operand.py) maps
 * each recorded address to its mnemonic with objdump and fails on any
 * mnemonic outside the vendor allowlist (tools/ct_operand/allowlists.json:
 * Intel's DOIT list, Arm's DIT list).
 *
 * Taint sources and sinks are Memcheck's own client requests, so every
 * existing taint driver and every AMA_CT_DECLASSIFY site in src/c works
 * unchanged: VALGRIND_MAKE_MEM_UNDEFINED taints a range, and
 * VALGRIND_MAKE_MEM_DEFINED (or _IF_ADDRESSABLE, or NOACCESS) clears it.
 *
 * What it does NOT do
 * -------------------
 * It does not report branches or addresses (Memcheck does that, bit-exactly;
 * this tool's propagation is coarser and would over-report them).  It does
 * not model the latency of anything: it reports operand flow, and the
 * allowlist decides.  Propagation is pessimistic, so a value that Memcheck's
 * bit-precise rules would call public (a secret ANDed with zero) is tainted
 * here; the zero idioms `x ^ x` and `x - x` are the only special cases.  An
 * over-taint can only add reports, never hide one.
 *
 * Licensing note: this file is Apache-2.0 source written against Valgrind's
 * public tool interface.  The executable it builds links Valgrind's GPL-2.0
 * core archives; it is test tooling built on the machine that runs it and is
 * never distributed with the library.
 */

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_machine.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_options.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_execontext.h"
#include "pub_tool_vki.h"
#include "pub_tool_aspacemgr.h"
#include "memcheck.h"

/* Generated at build time by tools/check_ct_operand.py from the installed
 * libvex_ir.h: ct_op_class(IROp) returns the CT_CLASS_* bits of an IR
 * operation.  Generated rather than written, so the division, square-root
 * and floating-point families are whatever this VEX version defines. */
#include "ct_opclass.h"

/* ------------------------------------------------------------------ */
/* Options and counters                                               */
/* ------------------------------------------------------------------ */

static const HChar *clo_out = NULL;

static ULong n_tainted_bytes = 0;     /* bytes marked by MAKE_MEM_UNDEFINED  */
static ULong n_declassified_bytes = 0;
static ULong n_taint_requests = 0;
static ULong n_consumptions = 0;      /* dynamic count of recorded events   */
static ULong n_sb_instrumented = 0;

/* ------------------------------------------------------------------ */
/* Shadow memory: one byte per client byte, 0 = public, 1 = tainted.   */
/* Chunks of 64 KiB, found through an open-addressed table.            */
/* ------------------------------------------------------------------ */

#define CHUNK_BITS 16
#define CHUNK_SIZE ((Addr)1 << CHUNK_BITS)
#define PM_SIZE    (1u << 16)

typedef struct { UChar b[CHUNK_SIZE]; } Chunk;

static Addr   pm_key[PM_SIZE];
static Chunk *pm_val[PM_SIZE];
static UInt   pm_used = 0;
static Addr   last_key = ~(Addr)0;
static Chunk *last_val = NULL;

static UInt pm_hash(Addr k) { return (UInt)((k * 0x9E3779B97F4A7C15ULL) >> 48) & (PM_SIZE - 1); }

static Chunk *chunk_for(Addr a, Bool create)
{
    Addr k = a >> CHUNK_BITS;
    if (k == last_key)
        return last_val;
    UInt h = pm_hash(k);
    for (UInt probe = 0; probe < PM_SIZE; probe++) {
        UInt i = (h + probe) & (PM_SIZE - 1);
        if (pm_val[i] == NULL) {
            if (!create)
                return NULL;
            tl_assert2(pm_used + 1 < PM_SIZE / 2, "ctoperand: shadow table full");
            Chunk *c = VG_(malloc)("ct.chunk", sizeof(Chunk));
            VG_(memset)(c, 0, sizeof(Chunk));
            pm_key[i] = k;
            pm_val[i] = c;
            pm_used++;
            last_key = k;
            last_val = c;
            return c;
        }
        if (pm_key[i] == k) {
            last_key = k;
            last_val = pm_val[i];
            return pm_val[i];
        }
    }
    tl_assert2(0, "ctoperand: shadow table probe exhausted");
    return NULL;
}

static void shadow_set_range(Addr a, SizeT len, UChar v)
{
    while (len > 0) {
        Chunk *c = chunk_for(a, v != 0);
        Addr off = a & (CHUNK_SIZE - 1);
        SizeT n = CHUNK_SIZE - off;
        if (n > len)
            n = len;
        if (c != NULL)
            VG_(memset)(&c->b[off], v, n);
        a += n;
        len -= n;
    }
}

static UWord shadow_any(Addr a, SizeT len)
{
    while (len > 0) {
        Chunk *c = chunk_for(a, False);
        Addr off = a & (CHUNK_SIZE - 1);
        SizeT n = CHUNK_SIZE - off;
        if (n > len)
            n = len;
        if (c != NULL) {
            for (SizeT i = 0; i < n; i++)
                if (c->b[off + i])
                    return 1;
        }
        a += n;
        len -= n;
    }
    return 0;
}

/* Helpers called from instrumented code. */
static VG_REGPARM(2) UWord ct_ld(Addr a, UWord size) { return shadow_any(a, size); }

static VG_REGPARM(3) void ct_st(Addr a, UWord size, UWord taint)
{
    shadow_set_range(a, size, taint ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/* Consumption sites                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    struct _VgHashNode *next;
    UWord key;            /* guest instruction address */
    ULong count;
    UWord classes;        /* CT_CLASS_* bits seen on a tainted operand */
    ExeContext *where;    /* call chain at first consumption */
} Site;

static VgHashTable *sites = NULL;

static VG_REGPARM(2) void ct_rec(Addr ip, UWord classes)
{
    n_consumptions++;
    Site *s = VG_(HT_lookup)(sites, ip);
    if (s == NULL) {
        s = VG_(malloc)("ct.site", sizeof(Site));
        s->key = ip;
        s->count = 0;
        s->classes = 0;
        s->where = VG_(record_ExeContext)(VG_(get_running_tid)(), 0);
        VG_(HT_add_node)(sites, s);
    }
    s->count++;
    s->classes |= classes;
}

/* ------------------------------------------------------------------ */
/* Instrumentation                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    IRSB   *out;
    IRTemp *sh;        /* shadow (Ity_I1) per original temp */
    Bool   *live;      /* original temp reaches an architectural effect */
    Bool   *branchy;   /* original temp reaches an exit guard or the next address */
    Int     n_orig;
    Int     gs_off;    /* offset of shadow area 1 in the guest state */
    IRExpr *cons;      /* I1 atom: did the current instruction read taint? */
    IRExpr *cls[5];    /* I1 atoms, one per CT_CLASS_* bit: DIV, FP, SQRT, BRANCH, OTHER */
    Addr    ip;        /* current guest instruction, 0 before the first IMark */
} Env;

static IRExpr *F1(void) { return IRExpr_Const(IRConst_U1(False)); }

static Bool is_false(const IRExpr *a)
{
    return a->tag == Iex_Const && a->Iex.Const.con->tag == Ico_U1 && !a->Iex.Const.con->Ico.U1;
}

static IRExpr *assign(Env *e, IRType ty, IRExpr *ex)
{
    IRTemp t = newIRTemp(e->out->tyenv, ty);
    addStmtToIRSB(e->out, IRStmt_WrTmp(t, ex));
    return IRExpr_RdTmp(t);
}

static IRExpr *or1(Env *e, IRExpr *a, IRExpr *b)
{
    if (is_false(a))
        return b;
    if (is_false(b))
        return a;
    return assign(e, Ity_I1, IRExpr_Binop(Iop_Or1, a, b));
}

/* (g ? a : b) on Ity_I1 values.  Written as (g & a) | (~g & b) because the
 * amd64 instruction selector has no rule for an Ity_I1-typed ITE (measured:
 * "iselCondCode_C(amd64)" on clang-built code); it does for And1/Or1/Not1. */
static IRExpr *ite1(Env *e, IRExpr *g, IRExpr *a, IRExpr *b)
{
    IRExpr *ga = is_false(a) ? a : assign(e, Ity_I1, IRExpr_Binop(Iop_And1, g, a));
    IRExpr *ng = assign(e, Ity_I1, IRExpr_Unop(Iop_Not1, g));
    IRExpr *gb = is_false(b) ? b : assign(e, Ity_I1, IRExpr_Binop(Iop_And1, ng, b));
    return or1(e, ga, gb);
}

static IRExpr *sh_atom(Env *e, IRExpr *a)
{
    if (a == NULL || a->tag == Iex_Const)
        return F1();
    if (a->tag == Iex_GSPTR || a->tag == Iex_VECRET)
        return F1();
    tl_assert(a->tag == Iex_RdTmp);
    IRTemp t = a->Iex.RdTmp.tmp;
    if ((Int)t >= e->n_orig)
        return F1(); /* one of our own temps: never a client value */
    if (e->sh[t] == IRTemp_INVALID)
        return F1(); /* temp not yet defined by a statement we instrument */
    return IRExpr_RdTmp(e->sh[t]);
}

static void set_sh(Env *e, IRTemp t, IRExpr *v)
{
    tl_assert((Int)t < e->n_orig);
    IRTemp s = newIRTemp(e->out->tyenv, Ity_I1);
    addStmtToIRSB(e->out, IRStmt_WrTmp(s, v));
    e->sh[t] = s;
}

static void consume(Env *e, IRExpr *taint) { e->cons = or1(e, e->cons, taint); }

/* Integer-typed shadow image of a guest-state slot of `size` bytes. */
static IRType int_ty_of_size(Int size)
{
    switch (size) {
    case 1:  return Ity_I8;
    case 2:  return Ity_I16;
    case 4:  return Ity_I32;
    case 8:  return Ity_I64;
    case 16: return Ity_V128;
    case 32: return Ity_V256;
    default: VG_(tool_panic)("ctoperand: unsupported guest-state access size");
    }
}

static IRExpr *nonzero(Env *e, IRType ity, IRExpr *x)
{
    IRExpr *w;
    switch (ity) {
    case Ity_I8:  w = assign(e, Ity_I64, IRExpr_Unop(Iop_8Uto64, x)); break;
    case Ity_I16: w = assign(e, Ity_I64, IRExpr_Unop(Iop_16Uto64, x)); break;
    case Ity_I32: w = assign(e, Ity_I64, IRExpr_Unop(Iop_32Uto64, x)); break;
    case Ity_I64: w = x; break;
    case Ity_V128: {
        IRExpr *lo = assign(e, Ity_I64, IRExpr_Unop(Iop_V128to64, x));
        IRExpr *hi = assign(e, Ity_I64, IRExpr_Unop(Iop_V128HIto64, x));
        w = assign(e, Ity_I64, IRExpr_Binop(Iop_Or64, lo, hi));
        break;
    }
    case Ity_V256: {
        IRExpr *a = assign(e, Ity_V128, IRExpr_Unop(Iop_V256toV128_0, x));
        IRExpr *b = assign(e, Ity_V128, IRExpr_Unop(Iop_V256toV128_1, x));
        IRExpr *na = nonzero(e, Ity_V128, a);
        IRExpr *nb = nonzero(e, Ity_V128, b);
        return or1(e, na, nb);
    }
    default: VG_(tool_panic)("ctoperand: nonzero of unsupported type");
    }
    return assign(e, Ity_I1, IRExpr_Binop(Iop_CmpNE64, w, IRExpr_Const(IRConst_U64(0))));
}

static IRExpr *widen(Env *e, IRType ity, IRExpr *t1)
{
    switch (ity) {
    case Ity_I8:  return assign(e, Ity_I8, IRExpr_Unop(Iop_1Sto8, t1));
    case Ity_I16: return assign(e, Ity_I16, IRExpr_Unop(Iop_1Sto16, t1));
    case Ity_I32: return assign(e, Ity_I32, IRExpr_Unop(Iop_1Sto32, t1));
    case Ity_I64: return assign(e, Ity_I64, IRExpr_Unop(Iop_1Sto64, t1));
    case Ity_V128: {
        IRExpr *w = widen(e, Ity_I64, t1);
        return assign(e, Ity_V128, IRExpr_Binop(Iop_64HLtoV128, w, w));
    }
    case Ity_V256: {
        IRExpr *v = widen(e, Ity_V128, t1);
        return assign(e, Ity_V256, IRExpr_Binop(Iop_V128HLtoV256, v, v));
    }
    default: VG_(tool_panic)("ctoperand: widen of unsupported type");
    }
}

static IRExpr *sh_get(Env *e, Int off, Int size)
{
    IRType ity = int_ty_of_size(size);
    IRExpr *g = assign(e, ity, IRExpr_Get(off + e->gs_off, ity));
    return nonzero(e, ity, g);
}

/* Shadow of an arbitrary guest-state region, chunked into legal accesses. */
static IRExpr *sh_get_region(Env *e, Int off, Int size)
{
    IRExpr *acc = F1();
    while (size > 0) {
        Int n = size >= 8 ? 8 : size >= 4 ? 4 : size >= 2 ? 2 : 1;
        acc = or1(e, acc, sh_get(e, off, n));
        off += n;
        size -= n;
    }
    return acc;
}

static void sh_put(Env *e, Int off, Int size, IRExpr *t1)
{
    IRType ity = int_ty_of_size(size);
    addStmtToIRSB(e->out, IRStmt_Put(off + e->gs_off, widen(e, ity, t1)));
}

static void sh_put_region_guarded(Env *e, Int off, Int size, IRExpr *t1, IRExpr *guard)
{
    while (size > 0) {
        Int n = size >= 8 ? 8 : size >= 4 ? 4 : size >= 2 ? 2 : 1;
        IRExpr *v = t1;
        if (guard != NULL) {
            IRExpr *old = sh_get(e, off, n);
            v = ite1(e, guard, t1, old);
        }
        sh_put(e, off, n, v);
        off += n;
        size -= n;
    }
}

static IRExpr *call_ld(Env *e, IRExpr *addr, Int size)
{
    IRTemp r = newIRTemp(e->out->tyenv, Ity_I64);
    IRDirty *d = unsafeIRDirty_1_N(r, 2, "ct_ld", VG_(fnptr_to_fnentry)(ct_ld),
                                   mkIRExprVec_2(addr, mkIRExpr_HWord((HWord)size)));
    addStmtToIRSB(e->out, IRStmt_Dirty(d));
    return assign(e, Ity_I1,
                  IRExpr_Binop(Iop_CmpNE64, IRExpr_RdTmp(r), IRExpr_Const(IRConst_U64(0))));
}

static void call_st(Env *e, IRExpr *addr, Int size, IRExpr *t1, IRExpr *guard)
{
    IRExpr *w = assign(e, Ity_I64, IRExpr_Unop(Iop_1Uto64, t1));
    IRDirty *d = unsafeIRDirty_0_N(3, "ct_st", VG_(fnptr_to_fnentry)(ct_st),
                                   mkIRExprVec_3(addr, mkIRExpr_HWord((HWord)size), w));
    if (guard != NULL)
        d->guard = guard;
    addStmtToIRSB(e->out, IRStmt_Dirty(d));
}

static void flush(Env *e)
{
    if (e->ip != 0 && !is_false(e->cons)) {
        IRExpr *mask = IRExpr_Const(IRConst_U64(0));
        for (Int k = 0; k < 5; k++) {
            if (is_false(e->cls[k]))
                continue;
            IRExpr *bit = assign(e, Ity_I64, IRExpr_Unop(Iop_1Uto64, e->cls[k]));
            IRExpr *sh = assign(e, Ity_I64, IRExpr_Binop(Iop_Shl64, bit, IRExpr_Const(IRConst_U8((UChar)k))));
            mask = assign(e, Ity_I64, IRExpr_Binop(Iop_Or64, mask, sh));
        }
        IRDirty *d = unsafeIRDirty_0_N(2, "ct_rec", VG_(fnptr_to_fnentry)(ct_rec),
                                       mkIRExprVec_2(mkIRExpr_HWord((HWord)e->ip), mask));
        d->guard = e->cons;
        addStmtToIRSB(e->out, IRStmt_Dirty(d));
    }
    e->cons = F1();
    for (Int k = 0; k < 5; k++)
        e->cls[k] = F1();
}

/* Record that an operation of class `bits` read an operand whose taint is
 * `taint`, for the current instruction. */
static void note_class(Env *e, UInt bits, IRExpr *taint)
{
    for (Int k = 0; k < 5; k++)
        if (bits & (1u << k))
            e->cls[k] = or1(e, e->cls[k], taint);
}

static Bool is_zero_idiom(const IRExpr *ex)
{
    if (ex->tag != Iex_Binop)
        return False;
    const IRExpr *a = ex->Iex.Binop.arg1, *b = ex->Iex.Binop.arg2;
    if (a->tag != Iex_RdTmp || b->tag != Iex_RdTmp || a->Iex.RdTmp.tmp != b->Iex.RdTmp.tmp)
        return False;
    switch (ex->Iex.Binop.op) {
    case Iop_Xor8: case Iop_Xor16: case Iop_Xor32: case Iop_Xor64:
    case Iop_Sub8: case Iop_Sub16: case Iop_Sub32: case Iop_Sub64:
    case Iop_XorV128: case Iop_XorV256:
        return True;
    default:
        return False;
    }
}

/* True when a constant operand fixes the result of `op` whatever the other
 * operand holds: OR with all ones, AND with zero (any width).  The same
 * bitwise "improvement" Memcheck makes (mc_translate.c), at the byte
 * granularity this tool keeps.  Without it, gcc 14's `or rax, -1` -- how it
 * materialises UINT64_MAX before a public `div` -- carried a stale secret
 * from rax into the dividend, and the divide was reported. */
static Bool const_fixes_result(IROp op, const IRExpr *c)
{
    if (c->tag != Iex_Const)
        return False;
    const IRConst *k = c->Iex.Const.con;
    Bool ones, zero;
    switch (k->tag) {
    case Ico_U8:   ones = k->Ico.U8 == 0xFF;               zero = k->Ico.U8 == 0;   break;
    case Ico_U16:  ones = k->Ico.U16 == 0xFFFF;            zero = k->Ico.U16 == 0;  break;
    case Ico_U32:  ones = k->Ico.U32 == 0xFFFFFFFFu;       zero = k->Ico.U32 == 0;  break;
    case Ico_U64:  ones = k->Ico.U64 == ~0ULL;             zero = k->Ico.U64 == 0;  break;
    case Ico_V128: ones = k->Ico.V128 == 0xFFFF;           zero = k->Ico.V128 == 0; break;
    case Ico_V256: ones = k->Ico.V256 == 0xFFFFFFFFu;      zero = k->Ico.V256 == 0; break;
    default:
        return False;
    }
    switch (op) {
    case Iop_Or8: case Iop_Or16: case Iop_Or32: case Iop_Or64:
    case Iop_OrV128: case Iop_OrV256:
        return ones;
    case Iop_And8: case Iop_And16: case Iop_And32: case Iop_And64:
    case Iop_AndV128: case Iop_AndV256:
        return zero;
    default:
        return False;
    }
}

/* Shadow of the value of a flat expression; also returns its own input taint. */
static IRExpr *sh_expr(Env *e, IRExpr *ex)
{
    switch (ex->tag) {
    case Iex_Const:
        return F1();
    case Iex_RdTmp:
        return sh_atom(e, ex);
    case Iex_Get:
        return sh_get(e, ex->Iex.Get.offset, sizeofIRType(ex->Iex.Get.ty));
    case Iex_GetI: {
        IRRegArray *d = ex->Iex.GetI.descr;
        IRType ity = int_ty_of_size(sizeofIRType(d->elemTy));
        IRRegArray *sd = mkIRRegArray(d->base + e->gs_off, ity, d->nElems);
        IRExpr *g = assign(e, ity, IRExpr_GetI(sd, ex->Iex.GetI.ix, ex->Iex.GetI.bias));
        return or1(e, nonzero(e, ity, g), sh_atom(e, ex->Iex.GetI.ix));
    }
    case Iex_Unop: {
        IRExpr *r = sh_atom(e, ex->Iex.Unop.arg);
        note_class(e, ct_op_class(ex->Iex.Unop.op), r);
        return r;
    }
    case Iex_Binop: {
        if (is_zero_idiom(ex) ||
            const_fixes_result(ex->Iex.Binop.op, ex->Iex.Binop.arg1) ||
            const_fixes_result(ex->Iex.Binop.op, ex->Iex.Binop.arg2))
            return F1();
        IRExpr *r = or1(e, sh_atom(e, ex->Iex.Binop.arg1), sh_atom(e, ex->Iex.Binop.arg2));
        note_class(e, ct_op_class(ex->Iex.Binop.op), r);
        return r;
    }
    case Iex_Triop: {
        IRTriop *t = ex->Iex.Triop.details;
        IRExpr *a = or1(e, sh_atom(e, t->arg1), sh_atom(e, t->arg2));
        IRExpr *r = or1(e, a, sh_atom(e, t->arg3));
        note_class(e, ct_op_class(t->op), r);
        return r;
    }
    case Iex_Qop: {
        IRQop *q = ex->Iex.Qop.details;
        IRExpr *a = or1(e, sh_atom(e, q->arg1), sh_atom(e, q->arg2));
        IRExpr *b = or1(e, sh_atom(e, q->arg3), sh_atom(e, q->arg4));
        IRExpr *r = or1(e, a, b);
        note_class(e, ct_op_class(q->op), r);
        return r;
    }
    case Iex_ITE: {
        IRExpr *a = or1(e, sh_atom(e, ex->Iex.ITE.cond), sh_atom(e, ex->Iex.ITE.iftrue));
        return or1(e, a, sh_atom(e, ex->Iex.ITE.iffalse));
    }
    case Iex_CCall: {
        IRExpr *acc = F1();
        for (Int i = 0; ex->Iex.CCall.args[i] != NULL; i++)
            acc = or1(e, acc, sh_atom(e, ex->Iex.CCall.args[i]));
        return acc;
    }
    case Iex_Load: {
        IRExpr *addr = ex->Iex.Load.addr;
        IRExpr *v = call_ld(e, addr, sizeofIRType(ex->Iex.Load.ty));
        return or1(e, v, sh_atom(e, addr));
    }
    default:
        ppIRExpr(ex);
        VG_(tool_panic)("ctoperand: unhandled expression");
    }
}

static void do_dirty(Env *e, IRStmt *st)
{
    IRDirty *d = st->Ist.Dirty.details;
    IRExpr *in = sh_atom(e, d->guard);
    for (Int i = 0; d->args[i] != NULL; i++)
        in = or1(e, in, sh_atom(e, d->args[i]));
    if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
        in = or1(e, in, call_ld(e, d->mAddr, d->mSize));
        in = or1(e, in, sh_atom(e, d->mAddr));
    }
    for (Int i = 0; i < d->nFxState; i++) {
        if (d->fxState[i].fx == Ifx_Read || d->fxState[i].fx == Ifx_Modify) {
            for (Int r = 0; r <= d->fxState[i].nRepeats; r++)
                in = or1(e, in,
                         sh_get_region(e, d->fxState[i].offset + r * d->fxState[i].repeatLen,
                                       d->fxState[i].size));
        }
    }
    consume(e, in);
    note_class(e, CT_CLASS_OTHER, in);
    addStmtToIRSB(e->out, st);
    /* A dirty call's guard is always present; a constant-true one needs no
     * guarding of the shadow writes below. */
    IRExpr *guard = (d->guard->tag == Iex_Const && d->guard->Iex.Const.con->Ico.U1) ? NULL : d->guard;
    if (d->tmp != IRTemp_INVALID)
        set_sh(e, d->tmp, in);
    for (Int i = 0; i < d->nFxState; i++) {
        if (d->fxState[i].fx == Ifx_Write || d->fxState[i].fx == Ifx_Modify) {
            for (Int r = 0; r <= d->fxState[i].nRepeats; r++)
                sh_put_region_guarded(e, d->fxState[i].offset + r * d->fxState[i].repeatLen,
                                      d->fxState[i].size, in, guard);
        }
    }
    if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify)
        call_st(e, d->mAddr, d->mSize, in, guard);
}

/* Backward liveness over the input block.  A temporary is live when its
 * value reaches an architectural effect -- a register write, a store, an
 * exit guard, a helper call, the block's next address -- directly or through
 * other live temporaries.  A WrTmp whose temporary is dead computes nothing
 * the instruction uses: VEX at --vex-iropt-level=0 still emits it (for
 * example the effective address of a multi-byte `nop`, which the
 * instruction ignores), and counting it as consumption would report an
 * operand the hardware never reads.  Effects themselves are always counted. */
static void mark(Bool *live, Int n, IRExpr *a)
{
    if (a != NULL && a->tag == Iex_RdTmp && (Int)a->Iex.RdTmp.tmp < n)
        live[a->Iex.RdTmp.tmp] = True;
}

static void mark_expr(Bool *live, Int n, IRExpr *ex)
{
    switch (ex->tag) {
    case Iex_RdTmp: mark(live, n, ex); break;
    case Iex_GetI: mark(live, n, ex->Iex.GetI.ix); break;
    case Iex_Unop: mark(live, n, ex->Iex.Unop.arg); break;
    case Iex_Binop: mark(live, n, ex->Iex.Binop.arg1); mark(live, n, ex->Iex.Binop.arg2); break;
    case Iex_Triop:
        mark(live, n, ex->Iex.Triop.details->arg1);
        mark(live, n, ex->Iex.Triop.details->arg2);
        mark(live, n, ex->Iex.Triop.details->arg3);
        break;
    case Iex_Qop:
        mark(live, n, ex->Iex.Qop.details->arg1);
        mark(live, n, ex->Iex.Qop.details->arg2);
        mark(live, n, ex->Iex.Qop.details->arg3);
        mark(live, n, ex->Iex.Qop.details->arg4);
        break;
    case Iex_ITE:
        mark(live, n, ex->Iex.ITE.cond);
        mark(live, n, ex->Iex.ITE.iftrue);
        mark(live, n, ex->Iex.ITE.iffalse);
        break;
    case Iex_CCall:
        for (Int i = 0; ex->Iex.CCall.args[i] != NULL; i++)
            mark(live, n, ex->Iex.CCall.args[i]);
        break;
    case Iex_Load: mark(live, n, ex->Iex.Load.addr); break;
    default: break;
    }
}

static void liveness(IRSB *in, Bool *live, Int n)
{
    for (Int i = 0; i < n; i++)
        live[i] = False;
    mark(live, n, in->next);
    for (Int i = in->stmts_used - 1; i >= 0; i--) {
        IRStmt *st = in->stmts[i];
        if (st == NULL)
            continue;
        switch (st->tag) {
        case Ist_WrTmp:
            if (live[st->Ist.WrTmp.tmp])
                mark_expr(live, n, st->Ist.WrTmp.data);
            break;
        case Ist_Put: mark(live, n, st->Ist.Put.data); break;
        case Ist_PutI: mark(live, n, st->Ist.PutI.details->ix); mark(live, n, st->Ist.PutI.details->data); break;
        case Ist_Store: mark(live, n, st->Ist.Store.addr); mark(live, n, st->Ist.Store.data); break;
        case Ist_StoreG:
            mark(live, n, st->Ist.StoreG.details->addr);
            mark(live, n, st->Ist.StoreG.details->data);
            mark(live, n, st->Ist.StoreG.details->guard);
            break;
        case Ist_LoadG:
            mark(live, n, st->Ist.LoadG.details->addr);
            mark(live, n, st->Ist.LoadG.details->alt);
            mark(live, n, st->Ist.LoadG.details->guard);
            break;
        case Ist_CAS:
            mark(live, n, st->Ist.CAS.details->addr);
            mark(live, n, st->Ist.CAS.details->expdHi);
            mark(live, n, st->Ist.CAS.details->expdLo);
            mark(live, n, st->Ist.CAS.details->dataHi);
            mark(live, n, st->Ist.CAS.details->dataLo);
            break;
        case Ist_LLSC: mark(live, n, st->Ist.LLSC.addr); mark(live, n, st->Ist.LLSC.storedata); break;
        case Ist_Dirty: {
            IRDirty *d = st->Ist.Dirty.details;
            mark(live, n, d->guard);
            mark(live, n, d->mAddr);
            for (Int k = 0; d->args[k] != NULL; k++)
                mark(live, n, d->args[k]);
            break;
        }
        case Ist_Exit: mark(live, n, st->Ist.Exit.guard); break;
        default: break;
        }
    }
}

/* Backward pass: which temporaries' values reach control flow -- an exit
 * guard or the block's next address -- through other temporaries.  BRANCH is
 * decided by this data flow, not by which instruction owns the exit
 * statement: CI's gcc 15.2.0 build of poly_basemul showed a `je` whose
 * consumption was recorded with no exit of its own (the guard it computed
 * was evaluated under a neighbouring `jbe`), so tagging only the exit's
 * instruction reported a conditional jump as an ordinary unlisted
 * instruction (2026-11-07). */
static void branch_flow(IRSB *in, Bool *branchy, Int n)
{
    for (Int i = 0; i < n; i++)
        branchy[i] = False;
    mark(branchy, n, in->next);
    for (Int i = in->stmts_used - 1; i >= 0; i--) {
        IRStmt *st = in->stmts[i];
        if (st == NULL)
            continue;
        if (st->tag == Ist_Exit)
            mark(branchy, n, st->Ist.Exit.guard);
        else if (st->tag == Ist_WrTmp && branchy[st->Ist.WrTmp.tmp])
            mark_expr(branchy, n, st->Ist.WrTmp.data);
    }
}

/* Charge `taint` as a non-branch use: a register write, a store, a helper
 * call, a guarded load, or an expression whose value reaches one of those. */
static void consume_other(Env *e, IRExpr *taint)
{
    consume(e, taint);
    note_class(e, CT_CLASS_OTHER, taint);
}

static IRSB *ct_instrument(VgCallbackClosure *closure, IRSB *in, const VexGuestLayout *layout,
                           const VexGuestExtents *vge, const VexArchInfo *archinfo,
                           IRType gWordTy, IRType hWordTy)
{
    (void)closure;
    (void)vge;
    (void)archinfo;
    (void)gWordTy;
    (void)hWordTy;
    n_sb_instrumented++;

    Env e;
    e.out = deepCopyIRSBExceptStmts(in);
    e.n_orig = in->tyenv->types_used;
    e.sh = VG_(malloc)("ct.sh", (e.n_orig ? e.n_orig : 1) * sizeof(IRTemp));
    for (Int i = 0; i < e.n_orig; i++)
        e.sh[i] = IRTemp_INVALID;
    e.live = VG_(malloc)("ct.live", (e.n_orig ? e.n_orig : 1) * sizeof(Bool));
    liveness(in, e.live, e.n_orig);
    e.branchy = VG_(malloc)("ct.branchy", (e.n_orig ? e.n_orig : 1) * sizeof(Bool));
    branch_flow(in, e.branchy, e.n_orig);
    e.gs_off = layout->total_sizeB;
    e.cons = F1();
    for (Int k = 0; k < 5; k++)
        e.cls[k] = F1();
    e.ip = 0;

    for (Int i = 0; i < in->stmts_used; i++) {
        IRStmt *st = in->stmts[i];
        if (st == NULL)
            continue;
        switch (st->tag) {
        case Ist_NoOp:
        case Ist_AbiHint:
        case Ist_MBE:
            addStmtToIRSB(e.out, st);
            break;
        case Ist_IMark:
            flush(&e);
            e.ip = (Addr)(st->Ist.IMark.addr + st->Ist.IMark.delta);
            addStmtToIRSB(e.out, st);
            break;
        case Ist_WrTmp: {
            IRExpr *data = st->Ist.WrTmp.data;
            IRExpr *s = sh_expr(&e, data);
            /* Consumption is charged to the instruction that USES a value as
             * an operand, not to the one that fetched it: VEX shares one
             * GET temp between instructions even at --vex-iropt-level=0 (a
             * clang padding `nop [rax+rax]` and the `and r9b, al` after it
             * read rax through one temp), so a fetch alone consumes nothing;
             * a load consumes its address, and every other expression its
             * arguments, which is what `s` is for them. */
            IRExpr *use = s;
            if (data->tag == Iex_Get)
                use = F1();
            else if (data->tag == Iex_Load)
                use = sh_atom(&e, data->Iex.Load.addr);
            else if (data->tag == Iex_GetI)
                use = sh_atom(&e, data->Iex.GetI.ix);
            if (e.live[st->Ist.WrTmp.tmp]) {
                if (e.branchy[st->Ist.WrTmp.tmp]) {
                    consume(&e, use);
                    note_class(&e, CT_CLASS_BRANCH, use);
                } else {
                    consume_other(&e, use);
                }
            }
            addStmtToIRSB(e.out, st);
            set_sh(&e, st->Ist.WrTmp.tmp, s);
            break;
        }
        case Ist_Put: {
            IRExpr *s = sh_atom(&e, st->Ist.Put.data);
            consume_other(&e, s);
            addStmtToIRSB(e.out, st);
            sh_put(&e, st->Ist.Put.offset,
                   sizeofIRType(typeOfIRExpr(in->tyenv, st->Ist.Put.data)), s);
            break;
        }
        case Ist_PutI: {
            IRPutI *p = st->Ist.PutI.details;
            IRExpr *s = or1(&e, sh_atom(&e, p->data), sh_atom(&e, p->ix));
            consume_other(&e, s);
            addStmtToIRSB(e.out, st);
            IRType ity = int_ty_of_size(sizeofIRType(p->descr->elemTy));
            IRRegArray *sd = mkIRRegArray(p->descr->base + e.gs_off, ity, p->descr->nElems);
            addStmtToIRSB(e.out, IRStmt_PutI(mkIRPutI(sd, p->ix, p->bias, widen(&e, ity, s))));
            break;
        }
        case Ist_Store: {
            IRExpr *a = sh_atom(&e, st->Ist.Store.addr);
            IRExpr *s = sh_atom(&e, st->Ist.Store.data);
            consume_other(&e, or1(&e, a, s));
            addStmtToIRSB(e.out, st);
            call_st(&e, st->Ist.Store.addr,
                    sizeofIRType(typeOfIRExpr(in->tyenv, st->Ist.Store.data)), s, NULL);
            break;
        }
        case Ist_StoreG: {
            IRStoreG *sg = st->Ist.StoreG.details;
            IRExpr *s = sh_atom(&e, sg->data);
            IRExpr *g = sh_atom(&e, sg->guard);
            consume_other(&e, or1(&e, or1(&e, sh_atom(&e, sg->addr), s), g));
            addStmtToIRSB(e.out, st);
            call_st(&e, sg->addr, sizeofIRType(typeOfIRExpr(in->tyenv, sg->data)), s, sg->guard);
            break;
        }
        case Ist_LoadG: {
            IRLoadG *lg = st->Ist.LoadG.details;
            IRType tyRes, tyArg;
            typeOfIRLoadGOp(lg->cvt, &tyRes, &tyArg);
            IRExpr *ls = or1(&e, call_ld(&e, lg->addr, sizeofIRType(tyArg)), sh_atom(&e, lg->addr));
            IRExpr *v = ite1(&e, lg->guard, ls, sh_atom(&e, lg->alt));
            v = or1(&e, v, sh_atom(&e, lg->guard));
            consume_other(&e, v);
            addStmtToIRSB(e.out, st);
            set_sh(&e, lg->dst, v);
            break;
        }
        case Ist_CAS: {
            IRCAS *c = st->Ist.CAS.details;
            Int sz = sizeofIRType(typeOfIRTemp(in->tyenv, c->oldLo));
            Int total = c->oldHi == IRTemp_INVALID ? sz : 2 * sz;
            IRExpr *ls = or1(&e, call_ld(&e, c->addr, total), sh_atom(&e, c->addr));
            IRExpr *in_t = or1(&e, or1(&e, sh_atom(&e, c->dataLo), sh_atom(&e, c->dataHi)),
                               or1(&e, sh_atom(&e, c->expdLo), sh_atom(&e, c->expdHi)));
            consume_other(&e, or1(&e, ls, in_t));
            addStmtToIRSB(e.out, st);
            set_sh(&e, c->oldLo, ls);
            if (c->oldHi != IRTemp_INVALID)
                set_sh(&e, c->oldHi, ls);
            call_st(&e, c->addr, total, or1(&e, ls, in_t), NULL);
            break;
        }
        case Ist_LLSC: {
            IRExpr *a = sh_atom(&e, st->Ist.LLSC.addr);
            if (st->Ist.LLSC.storedata == NULL) {
                IRType ty = typeOfIRTemp(in->tyenv, st->Ist.LLSC.result);
                IRExpr *ls = or1(&e, call_ld(&e, st->Ist.LLSC.addr, sizeofIRType(ty)), a);
                consume_other(&e, ls);
                addStmtToIRSB(e.out, st);
                set_sh(&e, st->Ist.LLSC.result, ls);
            } else {
                IRExpr *s = sh_atom(&e, st->Ist.LLSC.storedata);
                consume_other(&e, or1(&e, a, s));
                addStmtToIRSB(e.out, st);
                /* A failed store-conditional leaves memory unchanged, so its
                   shadow must be left unchanged too: guarded by RESULT (Ity_I1,
                   1 iff the store happened).  Unguarded, a public store attempt
                   on a secret-bearing word would clear the taint the word still
                   holds. */
                call_st(&e, st->Ist.LLSC.addr,
                        sizeofIRType(typeOfIRExpr(in->tyenv, st->Ist.LLSC.storedata)), s,
                        IRExpr_RdTmp(st->Ist.LLSC.result));
                set_sh(&e, st->Ist.LLSC.result, a);
            }
            break;
        }
        case Ist_Dirty:
            do_dirty(&e, st);
            break;
        case Ist_Exit:
            consume(&e, sh_atom(&e, st->Ist.Exit.guard));
            note_class(&e, CT_CLASS_BRANCH, sh_atom(&e, st->Ist.Exit.guard));
            flush(&e);
            addStmtToIRSB(e.out, st);
            break;
        default:
            ppIRStmt(st);
            VG_(tool_panic)("ctoperand: unhandled statement");
        }
    }
    /* The block's final jump target: an indirect jump or return on a value
     * the instruction read. */
    consume(&e, sh_atom(&e, in->next));
    note_class(&e, CT_CLASS_BRANCH, sh_atom(&e, in->next));
    flush(&e);
    VG_(free)(e.sh);
    VG_(free)(e.live);
    VG_(free)(e.branchy);
    return e.out;
}

/* ------------------------------------------------------------------ */
/* Client requests (Memcheck's codes), memory and register events       */
/* ------------------------------------------------------------------ */

static Bool ct_handle_client_request(ThreadId tid, UWord *arg, UWord *ret)
{
    (void)tid;
    if (!VG_IS_TOOL_USERREQ('M', 'C', arg[0]))
        return False;
    switch (arg[0]) {
    case VG_USERREQ__MAKE_MEM_UNDEFINED:
        shadow_set_range(arg[1], arg[2], 1);
        n_tainted_bytes += arg[2];
        n_taint_requests++;
        break;
    case VG_USERREQ__MAKE_MEM_DEFINED:
    case VG_USERREQ__MAKE_MEM_DEFINED_IF_ADDRESSABLE:
    case VG_USERREQ__MAKE_MEM_NOACCESS:
        shadow_set_range(arg[1], arg[2], 0);
        n_declassified_bytes += arg[2];
        break;
    default:
        break;
    }
    *ret = 0;
    return True;
}

static void clear_range(Addr a, SizeT len) { shadow_set_range(a, len, 0); }
static void clear_range_tid(Addr a, SizeT len, ThreadId tid) { (void)tid; clear_range(a, len); }
static void clear_startup(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di)
{
    (void)rr; (void)ww; (void)xx; (void)di;
    clear_range(a, len);
}
static void clear_mmap(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di)
{
    (void)rr; (void)ww; (void)xx; (void)di;
    clear_range(a, len);
}
static void post_mem_write(CorePart part, ThreadId tid, Addr a, SizeT len)
{
    (void)part; (void)tid;
    clear_range(a, len);
}
static void post_reg_write(CorePart part, ThreadId tid, PtrdiffT off, SizeT size)
{
    (void)part;
    UChar zeros[512];
    VG_(memset)(zeros, 0, sizeof zeros);
    while (size > 0) {
        SizeT n = size > sizeof zeros ? sizeof zeros : size;
        VG_(set_shadow_regs_area)(tid, 1, off, n, zeros);
        off += n;
        size -= n;
    }
}

/* ------------------------------------------------------------------ */
/* Report                                                               */
/* ------------------------------------------------------------------ */

static Int out_fd = -1;

static void outf(const HChar *fmt, ...) PRINTF_CHECK(1, 2);
static void outf(const HChar *fmt, ...)
{
    HChar buf[2048];
    va_list vargs;
    va_start(vargs, fmt);
    UInt n = VG_(vsnprintf)(buf, sizeof buf, fmt, vargs);
    va_end(vargs);
    if (n >= sizeof buf)
        n = sizeof buf - 1;
    VG_(write)(out_fd, buf, (Int)n);
}

static void print_frame(UInt n, DiEpoch ep, Addr ip, void *opaque)
{
    (void)opaque;
    if (n >= 8)
        return;
    outf("  frame %u %s\n", n, VG_(describe_IP)(ep, ip, NULL));
}

static void ct_fini(Int exitcode)
{
    (void)exitcode;
    if (clo_out == NULL)
        return;
    out_fd = VG_(fd_open)(clo_out, VKI_O_CREAT | VKI_O_WRONLY | VKI_O_TRUNC,
                          VKI_S_IRUSR | VKI_S_IWUSR);
    if (out_fd < 0) {
        VG_(umsg)("ctoperand: cannot open %s\n", clo_out);
        return;
    }
    DiEpoch ep = VG_(current_DiEpoch)();
    outf("ctoperand 3\n");
    outf("tainted_bytes %llu\n", n_tainted_bytes);
    outf("taint_requests %llu\n", n_taint_requests);
    outf("declassified_bytes %llu\n", n_declassified_bytes);
    outf("consumptions %llu\n", n_consumptions);
    outf("superblocks %llu\n", n_sb_instrumented);
    outf("sites %u\n", VG_(HT_count_nodes)(sites));
    UInt n = 0;
    VgHashNode **all = VG_(HT_to_array)(sites, &n);
    for (UInt i = 0; i < n; i++) {
        Site *s = (Site *)all[i];
        /* The file offset of the instruction, from the mapping that holds it.
         * This needs no symbol table (the shipped shared object is stripped
         * of one, so Valgrind builds no DebugInfo for it); the gate turns the
         * offset into a link-time address with the object's program headers. */
        NSegment const *seg = VG_(am_find_nsegment)(s->key);
        const HChar *obj = seg ? VG_(am_get_filename)(seg) : NULL;
        ULong file_off = seg ? (ULong)(s->key - seg->start) + (ULong)seg->offset : 0;
        outf("site 0x%lx %llu 0x%llx 0x%lx %s\n", s->key, s->count, file_off, s->classes,
             obj ? obj : "?");
        outf("  at %s\n", VG_(describe_IP)(ep, s->key, NULL));
        VG_(apply_ExeContext)(print_frame, NULL, s->where);
    }
    VG_(free)(all);
    outf("end\n");
    VG_(close)(out_fd);
}

static Bool ct_process_cmd_line_option(const HChar *arg)
{
    if VG_STR_CLO(arg, "--ct-out", clo_out) {
    } else
        return False;
    return True;
}

static void ct_print_usage(void) { VG_(printf)("    --ct-out=<file>   write the consumption report here\n"); }
static void ct_print_debug_usage(void) {}

static void ct_post_clo_init(void)
{
    if (clo_out == NULL)
        VG_(fmsg_bad_option)("--ct-out", "ctoperand requires --ct-out=<file>\n");
}

static void ct_pre_clo_init(void)
{
    VG_(details_name)("ctoperand");
    VG_(details_version)("1");
    VG_(details_description)("secret-operand consumption tracer (AMA Cryptography)");
    VG_(details_copyright_author)("Copyright (C) 2025-2026 Steel Security Advisors LLC");
    VG_(details_bug_reports_to)("https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/issues");
    VG_(details_avg_translation_sizeB)(640);
    VG_(basic_tool_funcs)(ct_post_clo_init, ct_instrument, ct_fini);
    VG_(needs_command_line_options)(ct_process_cmd_line_option, ct_print_usage,
                                    ct_print_debug_usage);
    VG_(needs_client_requests)(ct_handle_client_request);
    VG_(track_new_mem_startup)(clear_startup);
    VG_(track_new_mem_mmap)(clear_mmap);
    VG_(track_new_mem_brk)(clear_range_tid);
    VG_(track_new_mem_stack)(clear_range);
    VG_(track_new_mem_stack_signal)(clear_range_tid);
    VG_(track_post_mem_write)(post_mem_write);
    VG_(track_post_reg_write)(post_reg_write);
    sites = VG_(HT_construct)("ct.sites");
}

VG_DETERMINE_INTERFACE_VERSION(ct_pre_clo_init)
