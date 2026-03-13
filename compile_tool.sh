#!/bin/bash

# Define output directory and file
OUTPUT_DIR="./Output"
OUTPUT_FILE="$OUTPUT_DIR/IAPTool"

# Prompt the user to select the target platform
echo "Select the target platform for building the executable:"
echo "1. Windows"
echo "2. macOS"
echo "3. Linux"
read -p "Enter the corresponding number (1/2/3): " platform_choice

# Set GOOS and file extension based on the selected platform
case $platform_choice in
    1)
        PLATFORM="windows"
        EXTENSION=".exe"  # Windows executables require .exe extension
        OUTPUT_FILE="$OUTPUT_FILE$EXTENSION"
        ;;
    2)
        PLATFORM="darwin"
        EXTENSION=""  # macOS executables have no extension
        ;;
    3)
        PLATFORM="linux"
        EXTENSION=""  # Linux executables have no extension
        ;;
    *)
        echo "Invalid selection. Please enter 1, 2, or 3."
        exit 1
        ;;
esac

# Check if the Output directory exists
if [ -d "$OUTPUT_DIR" ]; then
    echo "Output directory exists: $OUTPUT_DIR"
    # If the target file exists, delete it
    if [ -f "$OUTPUT_FILE" ]; then
        echo "Removing existing file: $OUTPUT_FILE"
        rm "$OUTPUT_FILE"
    fi
else
    # Create the Output directory if it does not exist
    echo "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

# Display build information
echo "Building the executable for the '$PLATFORM' platform..."

# Set GOOS and GOARCH and run go build
GOOS=$PLATFORM GOARCH=amd64 go build -o "$OUTPUT_FILE"

# Check if the build succeeded
if [ $? -eq 0 ]; then
    echo "Build succeeded! The executable is saved at: $OUTPUT_FILE"
else
    echo "Build failed. Please check the error messages."
    exit 1
fi
