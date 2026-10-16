<?php
// Boat controller
namespace App\Http\Controllers;

use App\Models\Boat;
use Illuminate\Http\Request;
require_once 'helpers.php';

final class BoatController extends Controller
{
    public function index(Request $request)
    {
        # list boats
        return Boat::all();
    }

    private function validateBoat(array $data): bool
    {
        return isset($data['name']);
    }
}

function helper() { return 42; }
