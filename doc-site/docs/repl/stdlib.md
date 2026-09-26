# Standard-Library Functions

These functions serve as lightweight commands without crowding the `/<command>`
namespace.


| Function                 | Description                                                     |
|--------------------------|-----------------------------------------------------------------|
| `/std now`               | Displays the current date and time.                             |
| `/std new-day-alert`     | Makes AI aware when a new day begins since the last interaction.|
| `/std which <prog>`      | Checks if a specific program is available.                      |
| `/std io-backend`        | Display i/o type and capabilities.                              |

Using `/std now` is preferable to `/exec date`, as the latter requires user
confirmation to execute in untrusted tasks. The same reasoning applies to
`/std which` instead of `/exec which`.

The `/std new-day-alert` function is essential for ongoing, multi-day
conversations (e.g., calendar tasks). It ensures the AI is aware of a day
change so it can handle relative dates accurately.

The `/std io-backend` function is useful when instructing the LLM to output
differently depending on the i/o features available. For example, if the i/o
backend is `websocket`, the LLM can be instructed to output markdown links for
asset references since the display may be able to attach an `openLink` handler
to them. Valid outputs are `terminal - color`, `terminal - color, interactive`,
`websocket`, and `pipe`.
