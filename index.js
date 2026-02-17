const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

// --- config ---
const PORT = 3000; //--- sulis szerver miatt változni fog 
const HOST = 'localhost' //--- sulis szerver miatt változni fog 
const JWT_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'

// --- cookie beállítás ---
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 nap
}

// --- adatbázis beállítás ---
const db = mysql.createPool({
    host: 'localhost', //--- sulis szerver miatt változni fog 
    port: '3306', //--- sulis szerver miatt változni fog 
    user: 'root',
    password: '',
    database: 'szavazas'

})

// --- APP ---
const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: '*',
    credentials: true
}))

// --- végpontok ---

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return req.statusCode(400).send({ message: "Hiányzó bemeneti adatok" })
    }

    // --- ellenőrizni a felh nevet meg az emailt és hogy egyedi-e ---
    try {
        const isVAlid = await emailValidator(email)
        if (!isVAlid) {
            return res.status(401).json({ message: "Nem valós email cím" })
        }
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok Where email =? OR felhasznalonev = ?'
        const [exist] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exist.length) {
            return res.status(402).json({ message: "Az email cím vagy felhasználónév már foglalt" })
        }

        //--- regisztráció ---
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin ])

        //Válasz a felhasználónak
        return res.status(200).json({
            message: "Sikeres regisztráció",
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
        return res.status(400).json({ message: "Hiányos belépési adatok" });
    }

    try{
        const isVAlid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo="";
        let user ={}
        if (isVAlid) {
            const sql = 'SELECT * FROM felhasznalok Where email = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "Ezzel az emallel még nem regisztráltak" })
            }
        } else {

            const sql = 'SELECT * FROM felhasznalok Where felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(402).json({ message: "Ezzel az emallel még nem regisztráltak" })
            }

        }
        const ok = bcrypt.compare(jelszo,hashJelszo)  //felhasználónév vagy emailhez tartozó jelszó
        if (!ok) {
            return res.status(403).json({message:"Rossz jelszó"})
        }
        const token = jwt.sign(
            {id: user.id, email: user.email, felhasznalonev: user.felhasznalonev},
            JWT_SECRET,
            {experiesIN: JWT_EXPIRES_IN}
        )
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message:"Szerverhiba"})
    }
    catch (error){
        console.log(error);
        return res.status(500).json({message:"Szerverhiba"})
    }
})

//--- VÉDETT ---
app.get('/adataim', auth, async, (req, res)=>{
    
})


// --- szerver elindítása
app.listen(PORT, HOST, () => {
    console.log(`http://${HOST}:${POST}/`);

})