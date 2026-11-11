import mailbox, base64
box=mailbox.mbox('handover_mailbox.mbox')
for msg in box:
    value=msg.get('X-Northpier-Record')
    if value:
        print(base64.b64decode(value).decode())
