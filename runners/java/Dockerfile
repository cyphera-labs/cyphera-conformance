FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache openjdk-11 maven-3.9 && rm -rf /var/cache/apk/*
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk
ENV PATH="$JAVA_HOME/bin:/usr/share/java/maven/bin:$PATH"
WORKDIR /app
COPY pom.xml .
COPY src/ src/
RUN mvn package -B -q
WORKDIR /vectors
CMD ["java", "-jar", "/app/target/cyphera-test-runner-0.0.1.jar"]
