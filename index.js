const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

// -- config -- 
const PORT = 3000;
const HOST = 'localhost'
const jwt_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'

// cookie beállitás

const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 nap

}

// --- adatbázis beállitás ---
const db = mysql.createPool({
    host: 'localhost', // sulis szerver miatt majd átíródik
    port: '3306', // sulis szerver miatt majd átíródik
    user: 'root',
    password: '',
    database: 'szavazas'
})

// --- AP ---
const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))

// --- Middleware ----
function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME];
    if (!token) // le van járva a cookie --> nem érvényes
    {
        return res.status(409).json({ message: "Nincs bejelentkezés" })
    }
    try {
        // tokenbõl kinyerni a felhasználói adatokat
        req.user = jwt.verify(token, jwt_SECRET)
        next(); // haladhat tovább a végpontban
    } catch (error) {
        return res.status(410).json({ message: "Nem érvényes token" })
    }
}


// --- vegpontok ---

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    console.log(req.body);
    // bemeneti adatok ellenõrzése
    if (!email || !felhasznalonev || !jelszo || !(admin===0|| admin===1)) {
        return res.status(400).json({ message: "Hiányos bemeneti adatok" })
    }


    try {
        // valós email cím-e
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem valós emailt adtál meg" })
        }

        // ellenõrizni a felhasználónevet és emailt, hogy egyedi-e
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE email = ? OR felhasznalonev = ?'
        const [exists] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exists.length) {
            return res.status(402).json({ message: "Az email cim vagy felhasználónév foglalt" })
        }

        // regisztráció elvégzése
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

        // válasz a felhasználónak
        return res.status(200).json({
            message: "sikeres regisztráció",
            id: result.insertId
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Szerverhiba" })
    }

})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevVagyEmail, jelszo } = req.body;
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "hiányos belépési adatok" })
    }

    // meg kell kérdezni, hogy a megadott fiókhoz (email,felhasznalonev) milyen jelszó tartozik
    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = []
        if (isValid) {
            // email + jelszót adott meg belépéskor
            const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "Ezzel az email cimmel még nem regisztráltak" })
            }
        } else {
            // felhasználónév + jelszót adott meg belépéskor
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "Ezzel a felhasználónévvel még nem regisztráltak" })
            }
        }

        const ok = bcrypt.compare(jelszo, hashJelszo)//felhasznalonev vagy emailhez tartozó jelszó
        if (!ok) {
            return res.status(403).json({ message: "Rossz jelszót adtál meg!" })
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev },
            jwt_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        )

        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({ message: "Sikeres belépés" })

    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

// VÉDETT
app.post('/kijelentkezés', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "sikeres kijelentkezés" })
})


// VÉDETT
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})

//VÉDETT
app.put('/email', auth, async (req, res,) => {
    const { ujEmail } = req.body;
    // megnézem, hogy megadta-e body-ban az uj emailt a felhasznalo
    if (!ujEmail) {
        return res.status(401).json({ message: "Az új email megadása kötelezõ!" })
    }
    // megnézem, hogy az email formátuma megfelelõ
    const isValid = await emailValidator(ujEmail)
    if (!isValid) {
        return res.status(402).json({ message: "Az email cím formátuma nem megfelelõ" })
    }
    try {
        // megnézem, hogy az email szerepel-e a rendszerben
        const sql1 = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [result] = await db.query(sql1, [ujEmail])
        if (result.length) {
            return res.status(403).json({ message: "Az email cím már foglalt" })
        }
        // ha minden OK, akkor módositom az emailt
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE ID = ?'
        await db.query(sql2, [ujEmail, req.user.id]);
        return res.status(200).json({ message: "Az email módosítás végrehajtása sikeres" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Szerver Hiba" })
    }
})
app.put('/felhasznalonev', auth, async (req, res,) => {
    const { ujfelhasznalonev } = req.body;
    // megnézem, hogy megadta-e body-ban az uj emailt a felhasznalo
    if (!ujfelhasznalonev) {
        return res.status(401).json({ message: "Az új email megadása kötelezõ!" })
    }
    // megnézem, hogy az email formátuma megfelelõ
    const isValid = await emailValidator(ujfelhasznalonev)
    try {
        // megnézem, hogy az email szerepel-e a rendszerben
        const sql1 = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [result] = await db.query(sql1, [ujfelhasznalonev])
        if (result.length) {
            return res.status(403).json({ message: "Az email cím már foglalt" })
        }
        // ha minden OK, akkor módositom az emailt
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE ID = ?'
        await db.query(sql2, [ujfelhasznalonev, req.user.id]);
        return res.status(200).json({ message: "Az felhasznalonev módosítás végrehajtása sikeres" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Szerver Hiba" })
    }
})

app.put('/jelszo', async (req, res) => {
    const { jelenlegiJelszo, ujJelszo } = req.body;
    if (!jelenlegiJelszo || !ujJelszo) {
        return res.status(400).json({ message: "Hiányzó bemeneteli adatok" })
    }
    try {
        // a felhasznalohoz tartozó hash-elt jeslzót megkeresem
        const sql = 'SELECT * FROM  WHERE id = ?'
        const [rows] = await db.query(sql, [req.user.id]);
        user = rows[0];
        const hashJelszo = user.jelszo;
        //jelenlegi jelszot ossze vessuk az uj jelszoval
        const ok = bcrypt.compare(jelenlegiJelszo, hashJelszo)
        if (!ok) {
            return res.status(401).json({ message: "A régi jelszó nem helyes" })
        }
        //Uj jelszo has-eslese
        const hashUjJelszo = await bcrypt.hash(ujJelszo, 10)
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE ID = ?'
        await db.query(sql2, [hashUjJelszo, req.user.id]);
        return res.status(200).json({ message: "Sikeresen módosult a jelszavad" })

        // Uj jelszo beallitasa

    } catch (error) {
        res.status(500).json({ message: "szerverhiba" })
    }
})
app.delete('/fiokom', auth, async (req, res) => {
    try {
        // törölni kell a felhasználót
        const sql = 'DELETE FROM felhasznalok WHERE id = ?'
        await db.query(sql, [req.user.id])
        // utolsó lépés
        res.clearCookie(COOKIE_NAME, { path: '/' });
        res.status(200).json({ message: "Sikeres fióktörlés" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "szerverhiba" })
    }
})

// --- szerver elinditás ---
app.listen(PORT, HOST, () => {
    console.log(`API Fut: http://${HOST}:${PORT}/`)
})