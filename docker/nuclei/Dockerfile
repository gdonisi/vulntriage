# docker build -t my-nuclei:latest .
# docker run --rm my-nuclei <flags>
FROM projectdiscovery/nuclei:v3

# Nuclei official image uses Alpine, adding optional dependencies
RUN apk update && apk add --no-cache bash python3 php go ruby

# To avoid having to install the templates every time the program starts
RUN nuclei -ut
RUN echo "disable-update-check: true" > /root/.config/nuclei/config.yaml

ENTRYPOINT ["nuclei"]
CMD ["-h"]
