FROM maven:3.9-eclipse-temurin-11
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src/ src/
RUN mvn package -B -q
WORKDIR /vectors
CMD ["java", "-jar", "/app/target/cyphera-test-runner-0.0.1.jar"]
