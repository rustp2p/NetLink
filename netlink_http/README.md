## API

### 1. GET /api/application-info
 Retrieve application configuration.

### 2. GET /api/open
 Start using the current configuration.

### 3. GET /api/close
 Close the application.

### 4. GET /api/current-config
 Retrieve the latest configuration.

### 5. GET /api/started-config
 Retrieve the configuration used for starting the network. If the configuration has not been modified after starting the network, /api/current-config and /api/started-config will have the same values.

### 6. GET /api/current-info
 Retrieve current network information.

### 7. GET /api/current-nodes
 Retrieve information on the current group's nodes.

### 8. GET /api/groups
 Retrieve all group names.

### 9. GET /api/nodes-by-group/<group>
 Retrieve node information for the specified group.

### 10. POST /api/update-config
 Update the configuration.

### 10. other GET
 Read files from the `static` directory


