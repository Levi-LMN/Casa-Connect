# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy all files and build
COPY . .
RUN dotnet publish CasaConnect/CasaConnect.csproj -c Release -o out

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/out .

# Expose the Render-assigned port
ENV ASPNETCORE_URLS=http://+:$PORT
EXPOSE 8080

# Run your app
CMD ["dotnet", "CasaConnect.dll"]
