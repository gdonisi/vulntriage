FROM alpine:3
RUN apk update && apk add --no-cache nmap

ENTRYPOINT ["nmap"]
CMD ["--help"]
