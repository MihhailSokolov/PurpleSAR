FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && \
        apt-get install -y python3.10 git unzip python3-pip awscli curl wget vim lsb-release software-properties-common nano

RUN curl -s https://releases.hashicorp.com/terraform/1.4.5/terraform_1.4.5_linux_amd64.zip -o terraform.zip && \
         unzip terraform.zip && \
         mv terraform /usr/local/bin/

RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
RUN apt-add-repository "deb https://apt.releases.hashicorp.com $(lsb_release -cs) main"
RUN apt update && apt install packer

RUN git clone https://github.com/MihhailSokolov/PurpleSAR.git
RUN echo 'alias python=python3' >> ~/.bashrc

WORKDIR /PurpleSAR

RUN cd terraform/aws && terraform init
RUN cd terraform/azure && terraform init
RUN pip3 install poetry
RUN poetry install
RUN poetry self add poetry-plugin-shell
RUN pip3 install --upgrade awscli requests
RUN pip3 install azure-cli

COPY entrypoint.sh ./
RUN chmod +x ./entrypoint.sh
CMD ["./entrypoint.sh"]
