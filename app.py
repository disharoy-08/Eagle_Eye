from telnetlib import IP
from flask import Flask, request, url_for, render_template, redirect
from scapy.all import *
from prettytable import PrettyTable
from collections import Counter

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def submit():
    if request.method == "POST":
        file = request.form.get('myfile')
        return redirect(url_for('report', file=file))
    return render_template("index.html")    


@app.route('/report/<file>')
def report(file):
    packets = rdpcap(file)
    srcIP = []
    dstIP = []
    srcPort = []
    dstPort = []
    InFace = []
    strTime = []
    EndTime = []
    data = []
    headings = ("Source Ip","Destination Ip","Source Port","Destination Port")
    for pkt in packets:
             srcIP.append(pkt.src)
             print("\n")
             
             #srcPort.append(pkt.sport)
             #dstPort.append(pkt.dport)
    for pkt in packets:           
             dstIP.append(pkt.dst)
             print("\n")     
            
    cnt = Counter()
    for ip in srcIP:
        cnt[ip] += 1
    
 

    return render_template("report.html", headings = headings, sIp = srcIP, dIp = dstIP, sPort = srcPort, dPort = dstPort, length = cnt)


if __name__ == "__main__":
    app.run(debug=True, port=8000)
