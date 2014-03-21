# ldap server
IPASERVER="ldap://ipa.example.cz"
PW="secret123"

# vars for ldap search filter
FQDN="client1.example.cz"
HOSTNAME="client1"
DC="dc=example,dc=cz"
HOSTGROUP="clients"
NISGROUP="clients"

# can external user contain IP or network?
FILTER="
(&(&(objectClass=ipasudorule)(ipaEnabledFlag=TRUE))\
(|\
(cn=defaults)\
(externalHost=$HOSTNAME)\
(externalHost=$FQDN)\
(hostCategory=all)\
(hostCategory=ALL)\
(memberHost=fqdn=$FQDN,cn=computers,cn=accounts,$DC)\
(memberHost=cn=$HOSTGROUP,cn=hostgroups,cn=accounts,$DC)\
(memberHost=$NISGROUP)\
)\
)\
"

ldapsearch -x -H $IPASERVER -D "cn=Directory Manager" -w $PW $FILTER


# filter
filter='(&(&(objectClass=ipasudorule)(ipaEnabledFlag=TRUE))
		(|(cn=defaults)
			(externalHost=$HOSTNAME)
			(externalHost=$FQDN)
			(hostCategory=all)
			(hostCategory=ALL)
			(memberHost=fqdn=$FQDN,cn=computers,cn=accounts,$DN)
			(memberHost=cn=$HOSTGROUP,cn=hostgroups,cn=accounts,$DN)
			(memberHost=$NISGROUP)))'

echo $FILTER
# attributes
#cn ipaUniqueID
#externalHost hostCategory
#externalUser memberUser
#ipaSudoOpt
#ipaSudoRunAs 
#memberAllowCmd
#memberDenyCmd
