# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Fixed
- Corrected security weaknesses (#15, #16, #17, #18, #19, #20, #21, #22)

### Changed
- Enabled all compiler warning 

### Added
- Added files to make autoconf and automake happy (#29)

## [1.4.1] - 2015-10-23
### Changed
- Eliminated as many automake and autoconf generated files as possible (#10)
- Removed preprocessor directives checking for Windows (#11)

### Added
- travis-ci continuous integration (#12)
- coverity-scan security static code analysis (#13)

## [1.4.0] - 2015-10-03
### Changed
- Imported code from https://code.google.com/p/port-mirroring/ (version 1.3)
- Rebuilt automake files to compile against OpenWrt Designated Driver (Bleeding Edge, r47045)
