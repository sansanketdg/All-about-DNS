Name: Sanket Dige
Homework 1: All about DNS
CSE 534, Spring 2017
Instructor: Aruna Balasubramanian
==================================================================

For this programming assignment, dnsjava-2.1.7.jar external library was used which provides
a set of Classes and methods to make udp query request to various dns servers for query resolution.

PART A -

1. myDNSRESOLVEutil.java is the custom DNS resolvers that queries the 8 root servers on https://www.iana.org/domains/root/servers and recursively call respective authority servers till DNS query is resolved. To run this code, go to the PART A 
directory of the submission folder and run this command -

	For Linux based OS -
	-------------------------
	java -cp .:dnsjava-2.1.7.jar myDNSRESOLVEutil <domain to be resolved>

	For Windows OS -
	-------------------------
	java -cp .;dnsjava-2.1.7.jar myDNSRESOLVEutil <website name to be resolved>

2. myDIGutil.java is the custom dig implementation. To run this dig utility/ program, go to PART A directory of the submission folder and run this command -

	For Linux based OS -
	-------------------------
	java -cp .:dnsjava-2.1.7.jar myDIGutil <domain> <query-type>

	For Windows OS -
	-------------------------
	java -cp .;dnsjava-2.1.7.jar myDIGutil <domain> <query-type>

	NOTE -- Supported query-types here are A, MX, NS. By Default, the query will be made with type A if no type / invalid type is given. mydig_output.txt has the output for 3 query types - A, MX, NS supported by the myDIGutil program.

3. For cases like google.co.jp, when we do a query of type A, we receive a canonical name (CNAME) in the answer section of the query. Now to handle this, we need to requery this canonical name to find the actual IP of such websites. Hence, we don't get a resolved IP in one pass.
==================================================================

PART B - 

2. myDNSSECutil.java is the DNSSEC implementation. To run this program, go to PART B directory of the submission folder and run this command -

	For Linux based OS -
	-------------------------
	java -cp .:dnsjava-2.1.7.jar myDNSSECutil <domain>

	For Windows OS -
	-------------------------
	java -cp .;dnsjava-2.1.7.jar myDNSSECutil <domain>

PART C -

Here, the DNS performance was measured on 25 domains from alexa.com/topsites and the average values are stored in plotData.csv 
The CDF and the explanation part is in CDFanalysis.pdf file.

