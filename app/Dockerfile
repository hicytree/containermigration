FROM ubuntu:latest

# copy the file
COPY . /usr/bin/

WORKDIR /usr/bin/

# mark it as executable
RUN chmod +x looper.sh

# we'll start the simple bash script
CMD ["./looper.sh"]