package reporter

import "github.com/twsnmp/twlogeye/datastore"

func Init() {
	datastore.LoadServiceMap()
	syslogReporterCh = make(chan *datastore.SyslogEnt, 20000)
	trapReporterCh = make(chan *datastore.TrapLogEnt, 20000)
	netflowReporterCh = make(chan *datastore.NetflowLogEnt, 20000)
}
