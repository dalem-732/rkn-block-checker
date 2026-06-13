#!/bin/sh

APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit
JAVACMD="${JAVA_HOME:+$JAVA_HOME/bin/}java"

if ! command -v "$JAVACMD" >/dev/null 2>&1; then
    echo "ERROR: Java is required to run Gradle." >&2
    exit 1
fi

exec "$JAVACMD" \
    "-Dorg.gradle.appname=gradlew" \
    -classpath "$APP_HOME/gradle/wrapper/gradle-wrapper-main.jar:$APP_HOME/gradle/wrapper/gradle-wrapper-shared.jar" \
    org.gradle.wrapper.GradleWrapperMain "$@"
