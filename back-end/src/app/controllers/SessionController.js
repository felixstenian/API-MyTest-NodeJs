import jwt from "jsonwebtoken";
import * as Yup from "yup";

import User from "../models/User";
import authConfig from "../../config/auth";

class SessionController {
  async store(req, res) {
    const schema = Yup.object().shape({
      email: Yup.string()
        .email()
        .required(),
      password: Yup.string().required()
    });

    if (!(await schema.isValid(req.body))) {
      return res.status(400).json({ error: "Falha na Validação." });
    }
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: "Usuário não existe." });
    }

    if (!(await user.checkPassword(password))) {
      return res.status(401).json({ error: "Password invalido !" });
    }

    const { id, name } = user;

    return res.json({
      user: {
        id,
        name,
        email
      },
      token: jwt.sign({ id }, authConfig.secret, {
        expiresIn: authConfig.expiresIn
      })
    });
  }

  async update(req, res) {
    const [id, ,] = req.params.id.split("$");

    const user = await User.findOne({ where: { id } });

    const { name, user_name, email, avatar_id, active } = await user.update({
      active: true
    });

    return res.json({
      user: {
        id,
        name,
        user_name,
        email,
        avatar_id,
        active
      },
      token: jwt.sign({ id }, authConfig.secret, {
        expiresIn: authConfig.expiresIn
      })
    });
  }
}

export default new SessionController();
