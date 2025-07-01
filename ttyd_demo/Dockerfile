FROM ubuntu:24.04

# NOTE: Hardcoded to `hn_demo` user.

# Needed for build only
ARG DEMO_PASS
ENV DEMO_PASS=${DEMO_PASS}

# Install python3 for !py tool, vim for editor, /sqlite3/imagemagick for fun
RUN apt-get update && apt-get install -y \
    curl bash ttyd python3-full vim sqlite3 imagemagick \
    && rm -rf /var/lib/apt/lists/*

# Make image available as read-only
RUN curl -o /home/ubuntu/ducks.jpg https://i2.pickpik.com/photos/190/78/360/duck-chicken-family-wildlife-photography-preview.jpg
RUN chmod 444 /home/ubuntu/ducks.jpg

USER ubuntu
WORKDIR /home/ubuntu

# Install uv to demo !'uv' custom tool
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install hai
RUN curl -LsSf https://hai.superego.ai/hai-installer.sh | sh

# Login to hn_demo user
RUN /home/ubuntu/.local/bin/hai login hn_demo $DEMO_PASS

# Expose ttyd's default port
EXPOSE 1337

# To make uv available
ENV PATH="/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:${PATH}"
CMD ["ttyd", "--writable", "-p", "1337", "/home/ubuntu/.local/bin/hai", "-u", "hn_demo", "-m", "41"]
