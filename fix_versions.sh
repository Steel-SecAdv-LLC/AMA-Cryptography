#!/bin/bash
# Fix all version references to 2.0 (excluding Apache License 2.0)

# README.md
sed -i 's/# AMA Cryptography ♱ 2\.0/# AMA Cryptography ♱ 1.0/g' README.md
sed -i 's/AVA GUARDIAN ♱ 2\.0/AVA GUARDIAN ♱ 1.0/g' README.md
sed -i 's/Version: 2\.0\.0/Version: 1.0.0/g' README.md
sed -i "s/What's New in 2\.0/What's New in 1.0/g" README.md
sed -i 's/AMA Cryptography 2\.0/AMA Cryptography 1.0/g' README.md

# README_ENHANCED.md
sed -i 's/# AMA Cryptography ♱ 2\.0/# AMA Cryptography ♱ 1.0/g' README_ENHANCED.md
sed -i 's/AVA GUARDIAN ♱ 2\.0/AVA GUARDIAN ♱ 1.0/g' README_ENHANCED.md
sed -i 's/Version: 2\.0\.0/Version: 1.0.0/g' README_ENHANCED.md
sed -i "s/What's New in 2\.0/What's New in 1.0/g" README_ENHANCED.md
sed -i 's/AMA Cryptography 2\.0/AMA Cryptography 1.0/g' README_ENHANCED.md

# COMPLETION_REPORT.md
sed -i 's/AMA Cryptography ♱ 2\.0/AMA Cryptography ♱ 1.0/g' COMPLETION_REPORT.md
sed -i 's/AVA GUARDIAN ♱ 2\.0/AVA GUARDIAN ♱ 1.0/g' COMPLETION_REPORT.md
sed -i 's/AMA Cryptography 2\.0/AMA Cryptography 1.0/g' COMPLETION_REPORT.md

# SESSION_SUMMARY.md
sed -i 's/AMA Cryptography 2\.0/AMA Cryptography 1.0/g' SESSION_SUMMARY.md

# ENHANCED_FEATURES.md
sed -i 's/AMA Cryptography ♱ 2\.0/AMA Cryptography ♱ 1.0/g' ENHANCED_FEATURES.md
sed -i 's/AMA Cryptography 2\.0/AMA Cryptography 1.0/g' ENHANCED_FEATURES.md

echo "✓ Version references fixed to 1.0.0"
