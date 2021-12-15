##! Brigham Young University
##! Module for handling CIF intel extensions to the Intel framework
@load base/frameworks/intel

module cif_threat_intel_extend;

# These are some fields to add extended compatibility between Bro and the
# Collective Intelligence Framework.
# This was done here to mimic the loading of the CIF scripts on Corelight (collective intel scritp on Zeek)
# https://github.com/zeek/zeek/blob/master/scripts/policy/integration/collective-intel/main.zeek
redef record Intel::MetaData += {
	# Maps to the Impact field in the Collective Intelligence Framework.
	cif_impact:     string &optional;
	# Maps to the Severity field in the Collective Intelligence Framework.
	cif_severity:   string &optional;
	# Maps to the Confidence field in the Collective Intelligence Framework.
	cif_confidence: double &optional;
};

redef record Intel::Info += {
    cif_confidence: set[double] &optional &log;
    cif_severity: set[string] &optional &log;
    cif_impact: set[string] &optional &log;
};

hook Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set [Intel::Item]) : bool &priority=0 
{
    # Enumerate the items in the intel set and add appropriate records
    for ( item in items )
    {
        # Collective Intel Framework specific fields
        if(item$meta?$cif_confidence || item$meta?$cif_impact || item$meta?$cif_severity) {
            if ( ! info?$feed_source ) {
                info$feed_source = set();
            }
            add info$feed_source["cif"];
        }

        if(item$meta?$cif_confidence) {
            if ( ! info?$cif_confidence ) {
                info$cif_confidence = set();
            }
            add info$cif_confidence[item$meta$cif_confidence];
        }

        if(item$meta?$cif_severity) {
            if ( ! info?$cif_severity ) {
                info$cif_severity = set();
            }
            add info$cif_severity[item$meta$cif_severity];
        }

        if(item$meta?$cif_impact) {
            if ( ! info?$cif_impact ) {
                info$cif_impact = set();
            }
            add info$cif_impact[item$meta$cif_severity];
        }

    }
}

