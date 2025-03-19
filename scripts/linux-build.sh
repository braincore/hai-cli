#!/bin/bash
# linux-build.sh

# Get crate information
CRATE_NAME=$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].name')
VERSION=$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version')

# Get the binary name (will use the first binary target found)
BIN_NAME=$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].targets[] | select(.kind[] == "bin") | .name' | head -n1)

# If no binary target found, fall back to crate name
if [ -z "$BIN_NAME" ]; then
    BIN_NAME=$CRATE_NAME
    echo "No binary target found, using crate name: $BIN_NAME"
else
    echo "Using binary name: $BIN_NAME"
fi

echo "Building $CRATE_NAME version $VERSION"

# Create directory for outputs
mkdir -p releases

# Function to build and package a target
package_target() {
    local target=$1
    local os
    local arch
    
    # Parse OS and architecture from target triple
    if [[ $target == *"linux"* ]]; then
        os="linux"
    elif [[ $target == *"windows"* ]]; then
        os="windows"
    elif [[ $target == *"darwin"* ]]; then
        os="macos"
    else
        os="unknown"
    fi
    
    if [[ $target == "x86_64"* ]]; then
        arch="x86_64"
    elif [[ $target == "aarch64"* ]]; then
        arch="arm64"
    elif [[ $target == "armv7"* ]]; then
        arch="armv7"
    elif [[ $target == "arm-"* ]]; then
        arch="arm"
    else
        arch="unknown"
    fi
    
    echo "Building for $target ($os-$arch)..."
    
    if [[ $target == "x86_64-unknown-linux-gnu" ]]; then
        # Even for native target, use cross so that an older glibc is built
        # against.
        cross build --release --target "$target" || return 1
    else
        cross build --release --target "$target" || return 1
    fi
    
    # Create the package name
    local package_name="${CRATE_NAME}-${VERSION}-${os}-${arch}"
    local binary_path="../target/$target/release/$BIN_NAME"
    
    # Add .exe extension for Windows
    if [[ $os == "windows" ]]; then
        binary_path="${binary_path}.exe"
    fi
    
    if [ -f "$binary_path" ]; then
        echo "Packaging $package_name..."
        
        # Create a temp directory for packaging
        local temp_dir="target/package/$package_name"
        mkdir -p "$temp_dir"
        
        # Copy the binary
        cp "$binary_path" "$temp_dir/"
        
        # Create the archive
        if [[ $os == "windows" ]]; then
            # Use zip for Windows
            (cd "target/package" && zip -r "../../releases/$package_name.zip" "$package_name")
        else
            # Use tar.gz for Unix-like systems
            tar -czf "releases/$package_name.tar.gz" -C "target/package" "$package_name"
        fi
        
        # Clean up
        rm -rf "target/package/$package_name"
        
        if [[ $os == "windows" ]]; then
            echo "✅ Created releases/$package_name.zip"
        else
            echo "✅ Created releases/$package_name.tar.gz"
        fi
    else
        echo "❌ Binary not found at $binary_path"
    fi
    
    echo ""
}

# Linux targets
package_target "x86_64-unknown-linux-gnu"
package_target "aarch64-unknown-linux-gnu"
package_target "armv7-unknown-linux-gnueabihf"
package_target "arm-unknown-linux-gnueabihf"

# Windows target
package_target "x86_64-pc-windows-gnu"

echo "All packages have been saved to the 'releases' directory"
