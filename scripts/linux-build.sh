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
    
    # Use cross for all targets (even native x86_64 Linux) so that an older
    # glibc is built against.
    if ! cross build --release --target "$target"; then
        echo "❌ Build failed for $target"
        echo ""
        return 1
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
        echo ""
        return 1
    fi
    
    echo ""
}

ALL_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "armv7-unknown-linux-gnueabihf"
    "arm-unknown-linux-gnueabihf"
    "x86_64-pc-windows-gnu"
)

TARGETS=()
if [ $# -eq 0 ]; then
    TARGETS=("${ALL_TARGETS[@]}")
else
    for arg in "$@"; do
        case "$arg" in
            all)
                TARGETS+=("${ALL_TARGETS[@]}") ;;
            linux|windows)
                for t in "${ALL_TARGETS[@]}"; do
                    [[ $t == *"$arg"* ]] && TARGETS+=("$t")
                done ;;
            *-*-*)
                # Treat anything that looks like a target triple as a literal target
                TARGETS+=("$arg") ;;
            *)
                echo "Unknown target/group: $arg"
                echo "Usage: $0 [all|linux|windows|<target-triple>]..."
                exit 1 ;;
        esac
    done
fi

FAILED=()
for t in "${TARGETS[@]}"; do
    package_target "$t" || FAILED+=("$t")
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "❌ ${#FAILED[@]} of ${#TARGETS[@]} target(s) failed:"
    for t in "${FAILED[@]}"; do
        echo "   - $t"
    done
    exit 1
fi

echo "✅ All packages have been saved to the 'releases' directory"
