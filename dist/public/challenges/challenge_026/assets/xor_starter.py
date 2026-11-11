c1=bytes.fromhex("15232fdad7e08897b1d944446470000c2e51dfdbec8598b2a72925160778695a4bbc")
c2=bytes.fromhex("18383bf5f1d5b7b791ab7773524b2c050a23e2f0ca9fa58b9e614a56562c06584df1")
known=b"NORTHPIER-ARCHIVE-RECEIPT-00000000"
key=bytes(a^b for a,b in zip(c1,known))
print(bytes(a^b for a,b in zip(c2,key)).decode())
