FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /out
WORKDIR /vectors
CMD ["dotnet", "/out/Runner.dll"]
