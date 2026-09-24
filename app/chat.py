# app/chat.py
#
# SECURITY: the previous handler here trusted client-supplied sender_id /
# receiver_id and required no authentication, so anyone could forge chat
# messages as any user. It also overrode the authenticated handler in
# routes.py. The real-time chat handlers now live in routes.py
# (authenticated, per-user rooms, encrypted at rest).
