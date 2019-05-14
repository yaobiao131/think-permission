<?php
namespace xiaodi\Permission\Models;

use think\Model;
use xiaodi\Permission\Validate\Permission as Validate;

/**
 * 权限模型
 * 
 */
class Permission extends Model
{
    public function __construct($data = [])
    {
        $prefix = config('database.prefix');
        $name = config('permission.tables.permission');
        $table = [$prefix, $name];

        $this->pk = 'id';
        $this->table = implode('', $table);

        parent::__construct($data);
    }
}
