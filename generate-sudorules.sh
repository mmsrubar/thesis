for i in {1..500}; do
id=$(printf "%03d" $i)
suro_rule="sudorule$id"

ipa sudorule-add --hostcat=all $suro_rule
ipa sudorule-add-allow-command --sudocmds "/usr/bin/vim" $suro_rule
ipa sudorule-add-user --user usersssd05 $suro_rule
done

