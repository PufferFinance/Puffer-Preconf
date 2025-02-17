## Roles

| Role ID |           Full Title        |                    Description of the Role                                   |
| :-----: | :-------------------------: | :--------------------------------------------------------------------------- |
| 0       | ADMIN_ROLE                  | Administrative access for upgradability, only held by Timelock.              |
| 22      | ROLE_ID_OPERATIONS_MULTISIG | Operations multisig, manages operational tasks and transactions.             |
| 77      | ROLE_ID_DAO                 | DAOs role which after formation will control the protocol                    |
| max_int | PUBLIC_ROLE                 | Public role for public functions                                             |




# Contracts and Functions

## UniFiAVSManager

|                 Function                | Role ID |         Actor        |                  Remarks              |
|:---------------------------------------:|:-------:|:-------------------:|:--------------------------------------|
| setDeregistrationDelay                  | 77      | DAO                 |                                       |
| setChainID                              | 77      | DAO                 |                                       |
| updateAVSMetadataURI                          | 77      | DAO                 |                                       |
| registerOperator                        | max_int | Public              |                                       |
| registerValidators                      | max_int | Public              |                                       |
| startDeregisterOperator                 | max_int | Public              |                                       |
| finishDeregisterOperator                | max_int | Public              |
| deregisterValidators                    | max_int | Public              |                                       |
| setOperatorCommitment                   | max_int | Public              |                                       |
| registerOperatorWithCommitment          | max_int | Public              |                                       |
