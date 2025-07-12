const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Root Route for testing
app.get('/', (req, res) => {
  res.send('✅ Nutrition Tracker Server is Running!');
});

// ✅ MongoDB Atlas connection
mongoose.connect('mongodb://opsuser:12345678%40@ac-u7imqo0-shard-00-00.asa26qx.mongodb.net:27017,ac-u7imqo0-shard-00-01.asa26qx.mongodb.net:27017,ac-u7imqo0-shard-00-02.asa26qx.mongodb.net:27017/nutrition-tracker?replicaSet=atlas-7ier2j-shard-0&ssl=true&authSource=admin')
  .then(() => console.log('✅ Connected to MongoDB Atlas (No DNS Needed)'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// 🧠 User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// 🧠 Pantry Schema
const pantrySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  ingredients: [{ name: String, quantity: Number }],
});
const Pantry = mongoose.model('Pantry', pantrySchema);

// 🧠 Recipe Schema
const recipeSchema = new mongoose.Schema({
  name: String,
  ingredients: [String],
  instructions: [String],
});
const Recipe = mongoose.model('Recipe', recipeSchema);

// 🔐 JWT Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, 'secretkey');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// 🔁 Register Route
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 🔁 Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, 'secretkey');
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ➕ Add to Pantry
app.post('/api/pantry', authMiddleware, async (req, res) => {
  const { ingredient, quantity } = req.body;
  try {
    let pantry = await Pantry.findOne({ userId: req.user.userId });
    if (!pantry) {
      pantry = new Pantry({ userId: req.user.userId, ingredients: [] });
    }
    pantry.ingredients.push({ name: ingredient, quantity });
    await pantry.save();
    res.json({ message: 'Ingredient added', pantry });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 📦 Get Pantry
app.get('/api/pantry', authMiddleware, async (req, res) => {
  try {
    const pantry = await Pantry.findOne({ userId: req.user.userId });
    res.json(pantry || { ingredients: [] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 🍽️ Recipe Suggestions
app.get('/api/recipes', authMiddleware, async (req, res) => {
  try {
    const pantry = await Pantry.findOne({ userId: req.user.userId });
    const pantryIngredients = pantry ? pantry.ingredients.map(i => i.name.toLowerCase()) : [];
    const recipes = await Recipe.find();
    const matchedRecipes = recipes.filter(recipe =>
      recipe.ingredients.every(ing => pantryIngredients.includes(ing.toLowerCase()))
    );
    res.json(matchedRecipes);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 🚀 Start Server
app.listen(5000, () => console.log('🚀 Server running on port 5000'));