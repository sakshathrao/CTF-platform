import csv,itertools
P=170141183460469231731687303715884105727
with open("shares.csv",newline="") as f: rows=list(csv.DictReader(f))
sel=rows[:3]; xs=[int(r["x"]) for r in sel]; ys=[[int(v) for v in r["values"].split(",")] for r in sel]
out=[]
for j in range(len(ys[0])):
 val=0
 for i in range(3):
  num=den=1
  for k in range(3):
   if i!=k:num=num*(-xs[k])%P;den=den*(xs[i]-xs[k])%P
  val=(val+ys[i][j]*num*pow(den,-1,P))%P
 out.append(val)
print(bytes(out).decode())
