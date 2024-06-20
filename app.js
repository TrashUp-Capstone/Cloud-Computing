// Imports
const express = require('express');
const mysql = require('mysql');
const uuid = require('uuid');
const bcrypt = require('bcrypt');
const moment = require('moment');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const { Storage } = require('@google-cloud/storage');


const app = express()

app.use(express.json());


app.get('/', (req, res) => {
    return res.status(404).send({ message: 'Not found' });
});

app.post('/register/user', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hashed_password) {
        const id = uuid.v4();
        const { name, email, birth, phone, address } = req.body;
        const created_at = moment().format('yyyy-MM-DD hh:mm:ss');
        const insert_user = "INSERT INTO users (id, name, email, password, birth, phone, address, points, created_at) VALUES (?,?,?,?,?,?,?,?,?)"

        database.query(insert_user, [id, name, email, hashed_password, birth, phone, address, 0, created_at], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            const select_user = "SELECT * FROM users WHERE id = ?";

            database.query(select_user, [id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                const user = rows[0];

                return res.status(201).send({ data: user });
            });

        });
    });
});

app.post('/register/driver', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hashed_password) {
        const id = uuid.v4();
        const { name, email, address, birth, phone, license_plate } = req.body;
        const created_at = moment().format('yyyy-MM-DD hh:mm:ss');
        const insert_driver = "INSERT INTO drivers (id, name, email, password, address, birth, phone, license_plate, created_at) VALUES (?,?,?,?,?,?,?,?,?)"

        database.query(insert_driver, [id, name, email, hashed_password, address, birth, phone, license_plate, created_at], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            const select_driver = "SELECT * FROM drivers WHERE id = ?";

            database.query(select_driver, [id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                const driver = rows[0];

                return res.status(201).send({ data: driver });

            });

        });
    });
});

app.post('/login/user', (req, res) => {
    const { email, password } = req.body;
    const select_user = "SELECT * FROM users WHERE email = ?";

    database.query(select_user, [email], (err, rows, field) => {
        if (err) {
            return res.status(400).send({ message: err.sqlMessage });
        }

        if (rows.length < 1) {
            return res.status(404).send({ message: "User not found" });
        }

        const user = rows[0];

        bcrypt.compare(password, user.password, function (err, result) {
            if (result !== true) {
                return res.status(401).send({ message: "Unauthorized" });
            }

            crypto.randomBytes(48, function (err, buf) {
                const token = buf.toString('hex');
                const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
                const update_user = "UPDATE users SET token = ?, modified_at = ? WHERE id = ?";

                database.query(update_user, [token, modified_at, user.id], (err, rows, field) => {
                    if (err) {
                        return res.status(500).send({ message: err.sqlMessage });
                    }

                    return res.status(200).send({ token: token });
                })
            });
        });

    });
});


app.post('/login/driver', (req, res) => {
    const { email, password } = req.body;
    const select_driver = "SELECT * FROM drivers WHERE email = ?";

    database.query(select_driver, [email], (err, rows, field) => {
        if (err) {
            return res.status(400).send({ message: err.sqlMessage });
        }

        if (rows.length < 1) {
            return res.status(404).send({ message: "Driver not found" });
        }

        const driver = rows[0];

        bcrypt.compare(password, driver.password, function (err, result) {
            if (result !== true) {
                return res.status(401).send({ message: "Unauthorized" });
            }

            crypto.randomBytes(48, function (err, buf) {
                const token = buf.toString('hex');
                const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
                const update_driver = "UPDATE drivers SET token = ?, modified_at = ? WHERE id = ?";

                database.query(update_driver, [token, modified_at, driver.id], (err, rows, field) => {
                    if (err) {
                        return res.status(500).send({ message: err.sqlMessage });
                    }

                    return res.status(200).send({ token: token });
                })
            });
        });

    });
});


// Middleware
const authMiddleware = function (req, res, next) {
    const token = req.headers['authorization'].replace('Bearer ', '');
    const select_user = "SELECT * FROM users WHERE token = ?";

    database.query(select_user, [token], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.length > 0) {
            req.requester = rows[0];
            return next();
        }

        const select_driver = "SELECT * FROM drivers WHERE token = ?";
        database.query(select_driver, [token], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            if (rows.length > 0) {
                req.requester = rows[0];
                return next();
            }

            return res.status(401).send({ message: "Unauthorized" });
        });
    });
}


app.use(authMiddleware);

app.get('/whoami', (req, res) => {
    return res.status(200).send({ data: req.requester });
});

app.put('/whoami/update/user', (req, res) => {
    const { name, email, password, birth, phone, address } = req.body;

    bcrypt.compare(password, req.requester.password, function (err, result) {
        const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');

        if (result !== true) {
            bcrypt.hash(password, saltRounds, function (err, hashed_password) {
                const update_user = "UPDATE users SET name = ?, email = ?, password = ?, birth = ?, phone = ?, address = ?, modified_at = ? WHERE id = ?";
    
                database.query(update_user, [name, email, hashed_password, birth, phone, address, modified_at, req.requester.id], (err, rows, field) => {
                    if (err) {
                        return res.status(500).send({ message: err.sqlMessage });
                    }

                    if (rows.changedRows < 1) {
                        return res.status(404).send({ message: "User not found" });
                    }
            
                    return res.status(201).send({ message: "User updated successfully" });
                });
            });
        } else {
            const update_user = "UPDATE users SET name = ?, email = ?, birth = ?, phone = ?, address = ?, modified_at = ? WHERE id = ?";

            database.query(update_user, [name, email, birth, phone, address, modified_at, req.requester.id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                if (rows.changedRows < 1) {
                    return res.status(404).send({ message: "User not found" });
                }
        
                return res.status(201).send({ message: "User updated successfully" });
            });
        }
    });
});

app.put('/whoami/update/driver', (req, res) => {
    const { name, email, password, address, birth, phone, license_plate  } = req.body;

    bcrypt.compare(password, req.requester.password, function (err, result) {
        const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');

        if (result !== true) {
            bcrypt.hash(password, saltRounds, function (err, hashed_password) {
                const update_driver = "UPDATE drivers SET name = ?, email = ?, password = ?, address = ?, birth = ?, phone = ?, license_plate = ?, modified_at = ? WHERE id = ?";
    
                database.query(update_driver, [name, email, hashed_password, address, birth, phone, license_plate, modified_at, req.requester.id], (err, rows, field) => {
                    if (err) {
                        return res.status(500).send({ message: err.sqlMessage });
                    }

                    if (rows.changedRows < 1) {
                        return res.status(404).send({ message: "Driver not found" });
                    }
            
                    return res.status(201).send({ message: "Driver updated successfully" });
                });
            });
        } else {
            const update_driver = "UPDATE drivers SET name = ?, email = ?, address = ?, birth = ?, phone = ?, license_plate = ?, modified_at = ? WHERE id = ?";

            database.query(update_driver, [name, email, address, birth, phone, license_plate, modified_at, req.requester.id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                if (rows.changedRows < 1) {
                    return res.status(404).send({ message: "Driver not found" });
                }
        
                return res.status(201).send({ message: "Driver updated successfully" });
            });
        }
    });
});

app.put('/whoami/reset/user', (req, res) => {
    const { password } = req.body;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');

    bcrypt.hash(password, saltRounds, function (err, hashed_password) {
        const update_user = "UPDATE users SET password = ?, modified_at = ? WHERE id = ?";

        database.query(update_user, [hashed_password, modified_at, req.requester.id], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            if (rows.changedRows < 1) {
                return res.status(404).send({ message: "User not found" });
            }
    
            return res.status(201).send({ message: "User password reset successfully" });
        });
    });
});

app.put('/whoami/reset/driver', (req, res) => {
    const { password } = req.body;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');

    bcrypt.hash(password, saltRounds, function (err, hashed_password) {
        const update_user = "UPDATE drivers SET password = ?, modified_at = ? WHERE id = ?";

        database.query(update_user, [hashed_password, modified_at, req.requester.id], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            if (rows.changedRows < 1) {
                return res.status(404).send({ message: "Driver not found" });
            }
    
            return res.status(201).send({ message: "Driver password reset successfully" });
        });
    });
});

app.put('/logout/user', (req, res) => {
    const update_user = "UPDATE users SET token = ? WHERE id = ?";

    database.query(update_user, [null, req.requester.id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "User not found" });
        }

        return res.status(201).send({ message: "User no longer authorized" });
    })
});

app.put('/logout/driver', (req, res) => {
    const update_user = "UPDATE drivers SET token = ? WHERE id = ?";

    database.query(update_user, [null, req.requester.id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Driver not found" });
        }

        return res.status(201).send({ message: "Driver no longer authorized" });
    })
});

app.get('/lookups/activity', (req, res) => {
    const select_activity_statuses = "SELECT * FROM activity_statuses";

    database.query(select_activity_statuses, [], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const activity_statuses = rows;

        return res.status(200).send({ data: activity_statuses });
    })
});

app.get('/lookups/voucher', (req, res) => {
    const select_voucher_types = "SELECT * FROM voucher_types";

    database.query(select_voucher_types, [], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const voucher_types = rows;

        return res.status(200).send({ data: voucher_types });
    })
});

app.get('/lookups/waste', (req, res) => {
    const select_waste_types = "SELECT * FROM waste_types";

    database.query(select_waste_types, [], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const waste_types = rows;

        return res.status(200).send({ data: waste_types });
    })
});

app.get('/activities/user', (req, res) => {
    const select_activities = "SELECT * FROM activities WHERE user_id = ?";

    database.query(select_activities, [req.requester.id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const activities = rows;

        return res.status(200).send({ data: activities });
    })
});

app.get('/activities/driver', (req, res) => {
    const select_activities = "SELECT * FROM activities WHERE driver_id = ?";

    database.query(select_activities, [req.requester.id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const activities = rows;

        return res.status(200).send({ data: activities });
    })
});

app.get('/activities/ready', (req, res) => {
    const select_activities = `
        SELECT 
            activities.*, 
            users.name, 
            users.address 
        FROM 
            activities 
        JOIN 
            users 
        ON 
            activities.user_id = users.id 
        WHERE 
            activities.activity_status_id = ?`;

    database.query(select_activities, [2], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        const activities = rows;

        return res.status(200).send({ data: activities });
    });
});



app.post('/activities/new', (req, res) => {
    const id = uuid.v4();
    const user_id = req.requester.id;
    const activity_time = moment().format('yyyy-MM-DD 00:00:00');
    const { latitude, longitude } = req.body;
    const created_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const total_weight = 0;
    const points = 0;
    const activity_status_id = 1;
    const insert_activity = "INSERT INTO activities (id, user_id, activity_time, latitude, longitude, started_at, total_weight, points, activity_status_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)";

    database.query(insert_activity, [id, user_id, activity_time, latitude, longitude, created_at, total_weight, points, activity_status_id, created_at], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        return res.status(201).send({ message: "Activity successfully initialized", activity_id: id });
    });
});

app.put('/activities/update/ready', (req, res) => {
    const { id, total_weight, points } = req.body;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const update_activity = "UPDATE activities SET total_weight = ?, points = ?, activity_status_id = 2, modified_at = ? WHERE id = ? ";

    database.query(update_activity, [total_weight, points, modified_at, id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Activity not found" });
        }

        return res.status(201).send({ message: "Activity is ready to pick" });
    });
});

app.put('/activities/update/assign', (req, res) => {
    const id = req.body.id;
    const driver_id = req.requester.id;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const update_activity = "UPDATE activities SET driver_id = ?, activity_status_id = 3, modified_at = ? WHERE id = ? ";

    database.query(update_activity, [driver_id, modified_at, id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Activity not found" });
        }

        return res.status(201).send({ message: "Activity assigned by driver" });
    });
});

app.put('/activities/update/deliver', (req, res) => {
    const id = req.body.id;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const update_activity = "UPDATE activities SET activity_status_id = 4, modified_at = ? WHERE id = ? ";

    database.query(update_activity, [modified_at, id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Activity not found" });
        }

        return res.status(201).send({ message: "Activity is on going" });
    });
});

app.put('/activities/update/delivered', (req, res) => {
    const id = req.body.id;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const update_activity = "UPDATE activities SET ended_at = ?, activity_status_id = 5, modified_at = ? WHERE id = ? ";

    database.query(update_activity, [modified_at, modified_at, id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Activity not found" });
        }

        return res.status(201).send({ message: "Activity is delivered" });
    });
});

app.put('/activities/update/done', (req, res) => {
    const id = req.body.id;
    const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const update_activity = "UPDATE activities SET ended_at = ?, activity_status_id = 5, modified_at = ? WHERE id = ? ";

    database.query(update_activity, [modified_at, modified_at, id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.changedRows < 1) {
            return res.status(404).send({ message: "Activity not found" });
        }

        const select_activity = "SELECT * FROM activities WHERE id = ?";
        database.query(select_activity, [id], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            if (rows.length < 1) {
                return res.status(404).send({ message: "Activity not found" });
            }

            const activity = rows[0];
            const updated_points = req.requester.points + activity.points;
            const update_user = "UPDATE users SET points = ? WHERE id = ?";

            database.query(update_user, [updated_points, req.requester.id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                if (rows.changedRows < 1) {
                    return res.status(404).send({ message: "Activity not found" });
                }

                return res.status(201).send({ message: "Activity has done. Points successfully accumulated" })
            });
        })
    });
});

app.get('/activities/details', (req, res) => {
    const activity_id = req.query.activity_id;
    const select_activity_details = "SELECT * FROM activity_details WHERE activity_id = ?";

    database.query(select_activity_details, [activity_id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        return res.status(200).send({ data: rows });
    });
});

app.post('/activities/details', (req, res) => {
    const id = uuid.v4();
    const created_at = moment().format('yyyy-MM-DD hh:mm:ss');
    const { activity_id, waste_type_id, description, weight, photo } = req.body;
    const insert_activity_detail = "INSERT INTO activity_details (id, activity_id, waste_type_id, description, weight, photo, created_at) VALUES (?,?,?,?,?,?,?)"

    database.query(insert_activity_detail, [id, activity_id, waste_type_id, description, weight, photo, created_at], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        return res.status(201).send({ message: "Detail successfully sent", id: id });
    });
});

app.get('/vouchers', (req, res) => {
    const select_vouchers = "SELECT * FROM vouchers WHERE user_id = ?";

    database.query(select_vouchers, [req.requester.id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        return res.status(200).send({ data: rows });
    });
});

app.post('/activities/vouchers/new', (req, res) => {
    const voucher_type_id = req.body.voucher_type_id;
    const select_voucher_type = "SELECT * FROM voucher_types WHERE id = ?";

    database.query(select_voucher_type, [voucher_type_id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.length < 1) {
            return res.status(404).send({ message: "Voucher type not found" });
        }

        const voucher_type = rows[0];
        const id = uuid.v4();
        const points_after = req.requester.points - voucher_type.cost;
        const created_at = moment().format('yyyy-MM-DD hh:mm:ss');
        const insert_voucher = "INSERT INTO vouchers (id, user_id, voucher_type_id, points_before, points_after, is_used, created_at) VALUES (?,?,?,?,?,?,?)"

        database.query(insert_voucher, [id, req.requester.id, voucher_type.id, req.requester.points, points_after, 0, created_at], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            const update_user = "UPDATE users SET points = ? WHERE id = ?";

            database.query(update_user, [points_after, req.requester.id], (err, rows, field) => {
                if (err) {
                    return res.status(500).send({ message: err.sqlMessage });
                }

                if (rows.changedRows < 1) {
                    return res.status(404).send({ message: "User not found" });
                }

                return res.status(201).send({ message: "User points has claimed as voucher", id: id });
            });
        });
    });
});

app.put('/activities/vouchers/use', (req, res) => {
    const id = req.body.id;
    const select_voucher = "SELECT * FROM vouchers WHERE id = ?";

    database.query(select_voucher, [id], (err, rows, field) => {
        if (err) {
            return res.status(500).send({ message: err.sqlMessage });
        }

        if (rows.length < 1) {
            return res.status(404).send({ message: "Voucher not found" });
        }

        const voucher = rows[0];
        const modified_at = moment().format('yyyy-MM-DD hh:mm:ss');
        const update_voucher = "UPDATE vouchers SET is_used = ?, used_at = ?, modified_at = ? WHERE id = ?";

        database.query(update_voucher, [1, modified_at, modified_at, voucher.id], (err, rows, field) => {
            if (err) {
                return res.status(500).send({ message: err.sqlMessage });
            }

            if (rows.changedRows < 1) {
                return res.status(404).send({ message: "Voucher not found" });
            }

            return res.status(201).send({ message: "Voucher has used" })
        });
    });
});

const upload = multer({
    storage: multer.memoryStorage(), // Store files in memory temporarily
});

async function uploadFile(bucketName, file, fileOutputName) {
    try {
        const bucket = storage.bucket(bucketName);
        const result = await bucket.upload(file, { destination: fileOutputName });

        return result;
    } catch (err) {
        console.log('Error: ', err);
    }
}

app.post('/activities/details/upload', upload.single('photo'), async (req, res) => {

    if (!req.file) {
        return res.status(400).send({ message: "No file uploaded" })
    }

    await uploadFile('trashup-activity-details', req.file.originalname, req.requester.id + "/" + req.file.originalname);

    return res.status(201).send({ message: "Photo uploaded successfully" });
});

// app.listen(port, () => {
//     console.log(`Example app listening on port ${port}`)
// })

const PORT = process.env.PORT || 8000
app.listen(PORT, () => {
    console.log("Server is up and listening on " + PORT)
})