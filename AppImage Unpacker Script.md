Here's a shell script to unpack AppImage files to a directory on Ubuntu:

```bash
#!/bin/bash

# AppImage Unpacker Script
# Usage: ./unpack_appimage.sh <appimage_file> [output_directory]

# Check if AppImage file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <appimage_file> [output_directory]"
    echo "Example: $0 MyApp.AppImage /tmp/extracted"
    exit 1
fi

APPIMAGE_FILE="$1"
OUTPUT_DIR="${2:-$(basename "$APPIMAGE_FILE" .AppImage)_extracted}"

# Check if AppImage file exists
if [ ! -f "$APPIMAGE_FILE" ]; then
    echo "Error: AppImage file '$APPIMAGE_FILE' not found"
    exit 1
fi

# Check if file is executable
if [ ! -x "$APPIMAGE_FILE" ]; then
    echo "Making AppImage executable..."
    chmod +x "$APPIMAGE_FILE"
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Extracting '$APPIMAGE_FILE' to '$OUTPUT_DIR'..."

# Extract using --appimage-extract-and-run or --appimage-extract
if "$APPIMAGE_FILE" --appimage-extract >/dev/null 2>&1; then
    # Move extracted contents to specified directory
    if [ -d "squashfs-root" ]; then
        mv squashfs-root/* "$OUTPUT_DIR/" 2>/dev/null
        rmdir squashfs-root 2>/dev/null
        echo "Successfully extracted to: $OUTPUT_DIR"
    else
        echo "Error: Extraction failed - no squashfs-root directory found"
        exit 1
    fi
else
    echo "Error: Failed to extract AppImage"
    echo "Make sure the file is a valid AppImage"
    exit 1
fi

# List contents
echo "Contents extracted:"
ls -la "$OUTPUT_DIR"
```

To use this script:

1. Save it as `unpack_appimage.sh`
2. Make it executable: `chmod +x unpack_appimage.sh`
3. Run it: `./unpack_appimage.sh MyApp.AppImage [optional_output_dir]`

**Alternative one-liner commands:**

```bash
# Extract to default squashfs-root directory
./MyApp.AppImage --appimage-extract

# Extract and move to custom directory
./MyApp.AppImage --appimage-extract && mv squashfs-root MyApp_extracted
```

**Prerequisites:**
- The AppImage file must be executable (`chmod +x file.AppImage`)
- FUSE should be available (usually installed by default on Ubuntu)

The script handles error checking, creates the output directory if needed, and provides feedback on the extraction process.
