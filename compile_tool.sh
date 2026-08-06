#!/bin/bash

# Define output directory and base file name
OUTPUT_DIR="./Output"
BASE_NAME="IAPTool"

# Platforms to build: "GOOS:extension"
PLATFORMS=(
    "windows:.exe"
    "darwin:"
    "linux:"
)

for entry in "${PLATFORMS[@]}"; do
    PLATFORM="${entry%%:*}"
    EXTENSION="${entry#*:}"

    PLATFORM_DIR="$OUTPUT_DIR/$PLATFORM"
    OUTPUT_FILE="$PLATFORM_DIR/$BASE_NAME$EXTENSION"

    mkdir -p "$PLATFORM_DIR"

    echo "Building the executable for the '$PLATFORM' platform..."
    GOOS=$PLATFORM GOARCH=amd64 go build -o "$OUTPUT_FILE"

    if [ $? -eq 0 ]; then
        echo "Build succeeded! The executable is saved at: $OUTPUT_FILE"
    else
        echo "Build failed for platform '$PLATFORM'. Please check the error messages."
        exit 1
    fi
done
