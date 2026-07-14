FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache dotnet-8-sdk && rm -rf /var/cache/apk/*
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /out
WORKDIR /vectors
CMD ["dotnet", "/out/Runner.dll"]
