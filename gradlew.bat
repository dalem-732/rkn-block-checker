@echo off
setlocal

set DIRNAME=%~dp0
if "%DIRNAME%" == "" set DIRNAME=.
set APP_HOME=%DIRNAME%

set JAVA_EXE=%JAVA_HOME%\bin\java.exe
if exist "%JAVA_EXE%" goto execute
set JAVA_EXE=java.exe

:execute
"%JAVA_EXE%" "-Dorg.gradle.appname=gradlew" -classpath "%APP_HOME%\gradle\wrapper\gradle-wrapper-main.jar;%APP_HOME%\gradle\wrapper\gradle-wrapper-shared.jar" org.gradle.wrapper.GradleWrapperMain %*

endlocal
