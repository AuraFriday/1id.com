#!/bin/bash
# Build the oneid-keycloak-spi.jar
#
# Compiles against Keycloak 26.4.7 JARs on the server.
# Run from: ~/websites/1id.com/keycloak-spi/
#
# Usage: bash build.sh

set -e

KEYCLOAK_LIB="/opt/keycloak/lib/lib/main"
BUILD_DIR="./build"
OUTPUT_JAR="./oneid-keycloak-spi.jar"
SRC_DIR="./src/main/java"
RESOURCES_DIR="./src/main/resources"

echo "=== Building oneid-keycloak-spi.jar ==="

# Clean
rm -rf "$BUILD_DIR" "$OUTPUT_JAR"
mkdir -p "$BUILD_DIR"

# Build classpath from Keycloak JARs
# We need: keycloak-core, keycloak-server-spi, keycloak-server-spi-private, keycloak-services
CLASSPATH=""
for jar in \
  "$KEYCLOAK_LIB/org.keycloak.keycloak-core-26.4.7.jar" \
  "$KEYCLOAK_LIB/org.keycloak.keycloak-server-spi-26.4.7.jar" \
  "$KEYCLOAK_LIB/org.keycloak.keycloak-server-spi-private-26.4.7.jar" \
  "$KEYCLOAK_LIB/org.keycloak.keycloak-services-26.4.7.jar" \
  "$KEYCLOAK_LIB/com.mysql.mysql-connector-j-8.3.0.jar"; do
  if [ -f "$jar" ]; then
    CLASSPATH="$CLASSPATH:$jar"
  else
    echo "WARNING: JAR not found: $jar"
  fi
done
CLASSPATH="${CLASSPATH#:}"  # strip leading colon

echo "  Classpath: $(echo $CLASSPATH | tr ':' '\n' | wc -l) JARs"

# Compile
echo "  Compiling Java sources..."
find "$SRC_DIR" -name "*.java" -print0 | xargs -0 \
  javac -d "$BUILD_DIR" -cp "$CLASSPATH" -source 17 -target 17

# Copy META-INF/services
echo "  Copying resources..."
cp -r "$RESOURCES_DIR/META-INF" "$BUILD_DIR/"

# Package
echo "  Packaging JAR..."
cd "$BUILD_DIR"
jar cf "../$OUTPUT_JAR" .
cd ..

echo "  Built: $OUTPUT_JAR ($(wc -c < "$OUTPUT_JAR") bytes)"
echo "=== Done ==="
echo ""
echo "To deploy:"
echo "  sudo cp $OUTPUT_JAR /opt/keycloak/providers/"
echo "  sudo /opt/keycloak/bin/kc.sh build"
echo "  sudo systemctl restart keycloak"
