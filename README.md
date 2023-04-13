# letsencrypt_fortigate

This project intends to programatically install new letsencrypt certificates on fortigate firewall appliances. 
In the first release it already gets information about all let's encrypt certificates on all servers and their vdoms.

TO DO:
- Upload new certificate from a pre-generated one
- Update policies that use old certificates with newer ones
- Remove expired certificates
- Integrate own certificate generation logic
- Add logs on all operations and alert for certificates to expire
- Document the minimum set of API roles needed to run

DISCLAIMER:
NOT READY FOR PRODUCTION USE - For now just a proof of concept
