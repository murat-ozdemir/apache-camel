echo "Dont forget to set your own Java Home!"
export JAVA_HOME=/usr/lib/jvm/jdk-11.0.23+9/
mvn clean install -Pfastinstall --fail-at-end
