FROM embe221ed/otter_template:justctf2025@sha256:e0768a12564a1f76fd1c525be983f298b88705896c9fb95e1a52646d420f4f8d

ADD ./sources/run_client.sh /work/
ADD ./sources/framework-solve /work/framework-solve

WORKDIR /work/

CMD [ "./run_client.sh" ]
