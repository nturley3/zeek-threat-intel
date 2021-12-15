##! Brigham Young University
##! Extends the intel.log with additional fields
@load policy/frameworks/intel/seen

module threat_intel_extend;

# Adding default fields that are not normally included in the Intel::Info record
# Not all fields in this record are used. They have been left for future support.
redef record Intel::Info += {
    description: set[string] &optional &log;
    source: set[string] &optional &log;
    feed_source: set[string] &optional &log;
    url: set[string] &optional &log;
};

hook Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set [Intel::Item]) : bool &priority=0 
{
    # Enumerate the items in the intel set and add appropriate records
    for ( item in items )
    {
        # Add intel default fields that are not normally logged

        # Description field not currently used. Left for future support.
        #if(item$meta?$desc) {
        #    if ( ! info?$description ) {
        #        info$description = set();
        #    }
        #    add info$description[item$meta$desc];
        #}

        # Add url (from meta.url). This will normally be the ThreatQ reference URL
        if(item$meta?$url) {
            if ( ! info?$url ) {
                info$url = set();
            }
            add info$url[item$meta$url];
        }
    }
}
