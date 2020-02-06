FROM openjdk:13
COPY target/License3jrepl-3.1.4-jar-with-dependencies.jar /usr/src/License3jrepl-3.1.4-jar-with-dependencies.jar
WORKDIR /opt
CMD ["java" , "-jar", "/usr/src/License3jrepl-3.1.4-jar-with-dependencies.jar"]