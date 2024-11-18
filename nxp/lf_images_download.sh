#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2024 NXP

# Script to parse and download LF release images for DPDK supported platforms
# Set defaults
no_download=false
url=""
platform=""
output_dir="lf_images_$(date +%Y%m%d_%H%M%S)"

# Options string
opts=":u:p:o:ndh"

# Usage message
usage() {
  echo "Usage: $0 [options]"
  echo "  -u <URL>        Mandatory URL upto build ID (e.g. https://nl4-nxrm.sw.nxp.com/service/rest/repository/browse/Linux_Factory_Daily_Build/Linux_Factory/295/)"
  echo "  -p <platform>   Platform (e.g., imx8mm, imx8mp, imx8dxl, imx91, imx93, imx95)"
  echo "  -o <dir>        Output directory"
  echo "  -n              No download"
  echo "  -h              Show this help"
  exit 1
}

# Parse options
while getopts "$opts" opt; do
  case $opt in
    u) url="${OPTARG%/}";;
    p) platform="$OPTARG";;
    o) output_dir="$OPTARG";;
    n) no_download=true;;
    h) usage;;
    \?) usage;;  # Invalid option
    :) echo "Option -$OPTARG requires an argument"; usage;;
  esac
done

# Check mandatory URL option
if [ -z "$url" ]; then
  echo "Error: URL option (-u) is mandatory"
  usage
  exit 1
fi

# creating directory for logs and files
if [ -d "$output_dir" ]; then
  echo "Error: Directory '$output_dir' already exists."
  exit 1
fi
mkdir -p "$output_dir"

# Excluded directories
excluded_dirs=(
  bcu_tool
  documents
  imx-boot-tools
  stmm_capsule
  imx_mcore_demos
  imx_mfgtool_install_packages
  imx_porting_kit
  imx_revision_log
  optee-os-imx
  imx_uboot
)

# all parsed files
images_files=$output_dir/"parsed_files.txt"
> "$images_files"

logs=$output_dir/"logs.txt"
> "$logs"

date | tee -a "$logs"
# Platform-specific files to grep and download
declare -A platform_files
platform_files[imx95]="Image-imx95evk.bin
imx-boot-imx95-19x19-.*-evk-sd.bin-flash_a55
imx-image-full-imx95evk.rootfs-.*.tar.zst
imx95-19x19-evk.dtb"
platform_files[imx8mm]="imx-boot-imx8mmevk-sd.bin-flash_evk
Image-imx8mmevk.bin
imx-image-full-imx8mmevk.rootfs-.*.tar.zst
imx8mm-evk-dpdk.dtb"
platform_files[imx8mp]="imx-boot-imx8mpevk-sd.bin-flash_evk
Image-imx8mpevk.bin
imx-image-full-imx8mpevk.rootfs-.*.tar.zst
imx8mp-evk-dpdk.dtb"
platform_files[imx91]="imx-boot-imx91-11x11-.*-evk-sd.bin-flash_singleboot
Image-imx91evk.bin
imx-image-full-imx91evk.rootfs-.*.tar.zst
imx91-11x11-evk.dtb"
platform_files[imx93]="imx-boot-imx93-11x11-.*-evk-sd.bin-flash_singleboot
Image-imx93evk.bin
imx-image-full-imx93evk.rootfs-.*.tar.zst
imx93-11x11-evk.dtb"
platform_files[imx8dxl]="imx-boot-imx8dxlevk-sd.bin-flash_spl
Image-imx8dxlevk.bin
imx-image-full-imx8dxlevk.rootfs-.*.tar.zst
imx8dxl-evk.dtb"

# Function to get subdirectories and files
get_subdirs() {
  local url="$1"
  local depth="$2"

#  echo ${url}
  # Use wget to retrieve HTML content
  wget -q -O- "$url" | xmllint --html --xpath "//a[@href]/@href | //img[@src]/@src" - 2>/dev/null | sed 's/href=//g; s/src=//g; s/"//g' | while read -r line; do
    # Skip current/parent directories
    if [[ "$line" =~ ^\.\./ || "$line" =~ ^\.\/ || "$line" =~ ^\$ ||
          "${excluded_dirs[@]}" =~ (^| )"${line%%/*}"($| ) ]]; then
      continue
    fi

    # Check if line is a directory
    if [[ "$line" =~ /$ ]]; then
      # Print directory
      echo "${line} (Directory)" >> "$logs"

      # Recurse into subdirectory
      get_subdirs "${url}${line}" $((depth + 1))
    else
      # Print file
#      echo "${line} (File)"

      # Add files
      echo "$line" >> "$images_files"
    fi
  done
}

# URLs to parse
urls=(
  "${url}/common_bsp/"
  "${url}/fsl-imx-xwayland/"
)

# starting point
# Parse each URL
for url in "${urls[@]}"; do
  echo "Parsing $url"
  get_subdirs "$url" 0
done

# Display file count
file_count=$(wc -l < "$images_files")
echo "Total parsed Files: $file_count" | tee -a "$logs"

# Grep platform-specific files
if [ -n "$platform" ]; then
  if [[ ${platform_files[$platform]} ]]; then
    echo "Platform-specific files for $platform:" | tee -a "$logs"
    grep -E "${platform_files[$platform]}" "$images_files" | tee -a "$logs"
  else
    echo "Unsupported platform: $platform" | tee -a "$logs"
  fi
else
  echo "Path of all platform files:" | tee -a "$logs"
  for plat in "${!platform_files[@]}"; do
    echo "$plat:"
    grep -E "${platform_files[$plat]}" "$images_files" | tee -a "$logs"
    echo
  done
fi

if [ $no_download == true ]; then
	echo "Download skipped" | tee -a "$logs"
	date | tee -a "$logs"
	exit
fi
# Downloading files
mkdir -p "$output_dir/$platform"
# Download platform-specific files
if [ -n "$platform" ]; then
  if [[ ${platform_files[$platform]} ]]; then
    echo "Downloading Platform-specific files for $platform:" | tee -a "$logs"
    grep -E "${platform_files[$platform]}" "$images_files" | while read -r file; do
      wget -P "$output_dir/$platform" "${file}" >> "$logs"
      last_modified=$(stat -c "%y" "$output_dir/$platform/${file##*/}")
      echo "Downloaded ${file}" | tee -a "$logs"
      echo "last modified: ${last_modified}" | tee -a "$logs"
    done
  else
    echo "Unsupported platform: $platform" | tee -a "$logs"
  fi
else
  echo "Downloading files for all platforms" | tee -a "$logs"
  for plat in "${!platform_files[@]}"; do
    echo "$plat:"
    grep -E "${platform_files[$plat]}" "$images_files" | while read -r file; do
      wget -P "$output_dir/$plat" "${file}" >> "$logs"
      last_modified=$(stat -c "%y" "$output_dir/$platform/${file##*/}")
      echo "Downloaded ${file}" | tee -a "$logs"
      echo "last modified: ${last_modified}" | tee -a "$logs"
    done
    echo
  done
fi
date | tee -a "$logs"
