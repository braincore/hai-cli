#!/bin/bash
# macos-build.sh

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
    local arch
    
    # Parse architecture from target triple
    if [[ $target == "x86_64"* ]]; then
        arch="x86_64"
    elif [[ $target == "aarch64"* ]]; then
        arch="arm64"
    else
        arch="unknown"
    fi
    
    echo "Building for $target (macos-$arch)..."
    
    # Build for target
    cargo build --release --target "$target" || return 1
    
    # Create the package name
    local package_name="${CRATE_NAME}-${VERSION}-macos-${arch}"
    local binary_path="../target/$target/release/$BIN_NAME"
    
    if [ -f "$binary_path" ]; then
        echo "Packaging $package_name..."
        
        # Create a temp directory for packaging
        local temp_dir="target/package/$package_name"
        mkdir -p "$temp_dir"
        
        # Copy the binary
        cp "$binary_path" "$temp_dir/"
        
        # Create the archive
        tar -czf "releases/$package_name.tar.gz" -C "target/package" "$package_name"
        
        # Clean up
        rm -rf "target/package/$package_name"
        
        echo "✅ Created releases/$package_name.tar.gz"
    else
        echo "❌ Binary not found at $binary_path"
    fi
    
    echo ""
}

# macOS targets
package_target "x86_64-apple-darwin"
package_target "aarch64-apple-darwin"

echo "All macOS packages have been saved to the 'releases' directory"
