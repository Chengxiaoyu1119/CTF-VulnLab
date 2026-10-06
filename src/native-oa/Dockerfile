FROM alpine:3.20

RUN apk add --no-cache curl ca-certificates tzdata \
 && mkdir -p /app/backend/uploads/files /app/backend/uploads/avatars \
 && chown -R 65532:65532 /app/backend

ENV TZ=Asia/Shanghai
WORKDIR /app/backend

COPY --chown=65532:65532 oa-system /app/backend/oa-system
COPY --chown=65532:65532 config.yaml /app/backend/config.yaml
COPY --chown=65532:65532 dist /app/backend/dist

RUN chmod 0555 /app/backend/oa-system \
 && chmod -R a-w /app/backend/dist /app/backend/config.yaml \
 && chmod -R u+rwX /app/backend/uploads

EXPOSE 9090
USER 65532:65532
CMD ["./oa-system"]
