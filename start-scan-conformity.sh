#!/bin/bash
oscap xccdf eval  --results oscap-xccdf-result.xml  --profile anssi_bp28_enhanced  /usr/share/xml/scap/ssg/content/ssg-almalinux8-xccdf.xml
python3 insert-into-database-conformity.py
