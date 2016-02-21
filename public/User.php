<?php
class User
{

    public $id;

    public $name;

    public $privilage;

    public function __construct($id, $name, $privilage)
    {
        $this->id = $id;
        $this->name = $name;
        $this->privilage = $privilage;
    }

    public function authenticate($password) {
        return true;
    }

    public function allowAccess($privilages) {
        return in_array($this->privilage, $privilages, true);
    }

    static public function findBy($name)
    {
        if ($name === 'admin') {
            return self::findOne(10001);
        } else if ($name === 'test') {
            return self::findOne(10002);
        }
        return null;
    }

    static public function findOne($id)
    {
        if ($id === null) {
            return null;
        } else if ($id === 10001) {
            return new self(10001, 'admin', 'admin');
        } else if ($id === 10002) {
            return new self(10002, 'test', 'user');
        }
        return null;
    }
}

